//! Following the sampler across VPP runs (Linux).
//!
//! A [`Follower`] re-reads `current` (every 100 ms, by its caller) and
//! switches to the epoch it names when that changes: a VPP restart. The
//! consumer keeps `consumer.lock` throughout, so no other consumer can
//! claim the new epoch between switches, and unmaps the old one as it
//! switches, which is what lets the plugin's reclaim free its memory.
//! Samples still queued in an epoch it leaves are counted as abandoned:
//! the VPP that wrote them is gone, and so is any later chance to read
//! them.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::current::{Current, CurrentError};
use crate::fs::{open_epoch, Lock, OpenError, Opened, CONSUMER_LOCK, CURRENT};
use crate::layout::LayoutError;
use crate::ring;

/// An epoch change seen by [`Follower::refresh`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Switch {
    /// The epoch left, if one was open.
    pub from: Option<u64>,
    pub to: u64,
    /// Samples queued in the epoch left, never to be read.
    pub abandoned: u64,
}

pub struct Follower {
    dir: PathBuf,
    consume: bool,
    _lock: Option<Lock>,
    /// `current` as last read, to notice a change without parsing.
    seen: Option<String>,
    opened: Option<Opened>,
    error: Option<OpenError>,
}

impl Follower {
    /// The one consumer: takes `consumer.lock`, refused while another
    /// process holds it.
    pub fn consumer(dir: &Path) -> io::Result<Self> {
        let lock = Lock::try_exclusive(&dir.join(CONSUMER_LOCK))?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "another consumer holds consumer.lock",
            )
        })?;
        Ok(Self::new(dir, true, Some(lock)))
    }

    /// A read-only observer: never drains, never takes the lock.
    pub fn observer(dir: &Path) -> Self {
        Self::new(dir, false, None)
    }

    fn new(dir: &Path, consume: bool, lock: Option<Lock>) -> Self {
        Self {
            dir: dir.to_owned(),
            consume,
            _lock: lock,
            seen: None,
            opened: None,
            error: None,
        }
    }

    /// Re-reads `current`; opens the epoch it names when it changed (or
    /// when the last attempt failed). `Some` when the open epoch changed.
    pub fn refresh(&mut self) -> Option<Switch> {
        let text = fs::read_to_string(self.dir.join(CURRENT)).ok();
        if text.is_some() && text == self.seen && self.opened.is_some() {
            return None;
        }
        if text.is_none() {
            // Nothing to switch to; the epoch open (if any) stays, and its
            // heartbeat says whether it is still alive.
            if self.opened.is_none() {
                self.error = Some(OpenError::NoCurrent);
            }
            return None;
        }
        match open_epoch(&self.dir, self.consume) {
            Ok(new) => {
                self.seen = text;
                self.error = None;
                let to = new.header.epoch;
                let old = self.opened.replace(new);
                match old {
                    Some(o) if o.header.epoch == to => None,
                    old => {
                        let from = old.as_ref().map(|o| o.header.epoch);
                        let abandoned = old.as_ref().map_or(0, queued_in);
                        // `old` is unmapped here, as it is dropped.
                        Some(Switch {
                            from,
                            to,
                            abandoned,
                        })
                    }
                }
            }
            Err(e) => {
                // A new `current` that cannot be opened leaves the old
                // epoch open: if its VPP is gone, its heartbeat says so.
                self.error = Some(e);
                None
            }
        }
    }

    pub fn opened(&self) -> Option<&Opened> {
        self.opened.as_ref()
    }

    /// Why the last attempt to open an epoch failed, if it did.
    pub fn error(&self) -> Option<&OpenError> {
        self.error.as_ref()
    }

    /// Whether the last failure was a format this build cannot read: a
    /// newer `current` or epoch layout, which no amount of waiting fixes.
    pub fn incompatible(&self) -> bool {
        matches!(
            self.error,
            Some(
                OpenError::Incompatible(_)
                    | OpenError::Current(CurrentError::Version(_))
                    | OpenError::Layout(LayoutError::Version { .. })
            )
        )
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The epoch `current` names, without opening it.
    pub fn current(&self) -> Option<Current> {
        self.seen.as_deref().and_then(|t| Current::parse(t).ok())
    }
}

/// Samples written to a ring but not yet consumed, from one look at its
/// counters. `head` is read before `tail`, so a consumer draining
/// meanwhile can leave `tail` past the `head` seen: nothing queued.
pub fn queued(c: &ring::Counters) -> u64 {
    c.head.saturating_sub(c.tail)
}

fn queued_in(o: &Opened) -> u64 {
    (0..o.layout().workers)
        .map(|r| queued(&ring::counters(o.layout(), o.file(), r)))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{create_epoch, ensure_dir, publish_current, random_epoch, Mapping};
    use crate::layout::Layout;
    use crate::ring::{RingWriter, SampleMeta};
    use crate::Class;

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-shm-follow-{}", random_epoch()));
        ensure_dir(&d).unwrap();
        d
    }

    fn meta() -> SampleMeta {
        SampleMeta {
            generation: 1,
            time_ns: 1,
            sw_if_index: 1,
            class: Class::Ingress,
            pool_index: 0,
            rate: 1,
            frame_len: 64,
        }
    }

    /// A VPP run: an epoch, published.
    fn run(d: &Path, epoch: u64) -> (Layout, Mapping) {
        let l = Layout::new(2, 8, 16).unwrap();
        let m = create_epoch(d, &l, epoch, 0, 0, "test").unwrap();
        publish_current(d, epoch, &l).unwrap();
        (l, m)
    }

    #[test]
    fn a_consumer_follows_restarts_and_counts_what_it_leaves() {
        let d = tempdir();
        let mut f = Follower::consumer(&d).unwrap();
        assert_eq!(f.refresh(), None);
        assert!(matches!(f.error(), Some(OpenError::NoCurrent)));

        let (l, m) = run(&d, 1);
        assert_eq!(
            f.refresh(),
            Some(Switch {
                from: None,
                to: 1,
                abandoned: 0
            })
        );
        assert_eq!(f.refresh(), None, "same current, no switch");
        let w = RingWriter::new(&l, m.words(), 1);
        for _ in 0..3 {
            assert!(w.push(&meta(), b"x"));
        }
        let mut out = Vec::new();
        f.opened().unwrap().ring(1).unwrap().drain(&mut out, 1);
        assert_eq!(out.len(), 1);

        // VPP restarts with two samples still queued.
        let (_l2, _m2) = run(&d, 2);
        assert_eq!(
            f.refresh(),
            Some(Switch {
                from: Some(1),
                to: 2,
                abandoned: 2
            })
        );
        assert_eq!(f.opened().unwrap().header.epoch, 2);
        assert!(Follower::consumer(&d).is_err(), "one consumer at a time");
        drop(f);
        assert!(Follower::consumer(&d).is_ok(), "the lock goes with it");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_observer_reads_but_cannot_drain_and_takes_no_lock() {
        let d = tempdir();
        let _consumer = Follower::consumer(&d).unwrap();
        let (_l, _m) = run(&d, 7);
        let mut o = Follower::observer(&d);
        assert!(o.refresh().is_some());
        let opened = o.opened().unwrap();
        assert!(opened.ring(0).is_none());
        assert!(opened.status().read().is_ok());
        assert_eq!(o.current().unwrap().epoch, 7);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_tail_past_the_head_seen_is_nothing_queued() {
        let c = |head, tail| ring::Counters {
            head,
            tail,
            selected: 0,
            written: 0,
            dropped_full: 0,
            pool: Vec::new(),
        };
        assert_eq!(queued(&c(10, 4)), 6);
        assert_eq!(queued(&c(10, 12)), 0, "a drain between the two loads");
    }

    #[test]
    fn an_unreadable_new_epoch_keeps_the_old_one_open() {
        let d = tempdir();
        let (_l, _m) = run(&d, 3);
        let mut f = Follower::observer(&d);
        f.refresh();
        std::fs::write(d.join(CURRENT), "pf-sampler-current 1\nepoch 0000000000000009\nfile epoch-0000000000000009.shm\nlayout 1\nsize 8\n").unwrap();
        assert_eq!(f.refresh(), None);
        assert_eq!(f.opened().unwrap().header.epoch, 3);
        assert!(f.error().is_some());
        std::fs::write(d.join(CURRENT), "pf-sampler-current 1\nepoch 0000000000000009\nfile epoch-0000000000000009.shm\nlayout 2\nsize 8\n").unwrap();
        f.refresh();
        assert!(f.incompatible());
        // A newer `current` format is as permanent as a newer layout.
        std::fs::write(
            d.join(CURRENT),
            "pf-sampler-current 2\nepoch 0000000000000009\n",
        )
        .unwrap();
        f.refresh();
        assert!(f.incompatible(), "{:?}", f.error());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
