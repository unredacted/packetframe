//! `current`: which epoch file to read.
//!
//! The plugin writes it, by rename, only after the epoch file it names is
//! fully initialised and marked ready. Readers re-read it every 100 ms and
//! switch when it changes. The file name is derived from the epoch and
//! checked, so a reader never opens a path the pointer merely claims.
//!
//! ```text
//! pf-sampler-current 1
//! epoch 1f2e3d4c5b6a7988
//! file epoch-1f2e3d4c5b6a7988.shm
//! layout 1
//! size 1441792
//! ```

use crate::layout;

const MAGIC: &str = "pf-sampler-current";
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    pub epoch: u64,
    /// The epoch file's layout version.
    pub layout: u64,
    /// The epoch file's size in bytes.
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CurrentError {
    #[error("`current` is malformed: {0}")]
    Malformed(&'static str),
    #[error("`current` has format version {0}; this build reads version {VERSION}")]
    Version(String),
}

/// The name of an epoch's file in the sampler directory.
pub fn epoch_file_name(epoch: u64) -> String {
    format!("epoch-{epoch:016x}.shm")
}

/// Whether `name` is an epoch file's name (any epoch).
pub fn is_epoch_file_name(name: &str) -> bool {
    name.strip_prefix("epoch-")
        .and_then(|r| r.strip_suffix(".shm"))
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl Current {
    pub fn file_name(&self) -> String {
        epoch_file_name(self.epoch)
    }

    pub fn render(&self) -> String {
        format!(
            "{MAGIC} {VERSION}\nepoch {:016x}\nfile {}\nlayout {}\nsize {}\n",
            self.epoch,
            self.file_name(),
            self.layout,
            self.size
        )
    }

    pub fn parse(text: &str) -> Result<Self, CurrentError> {
        let malformed = CurrentError::Malformed;
        let mut lines = text.lines();
        let mut field = |key: &str| -> Result<&str, CurrentError> {
            lines
                .next()
                .and_then(|l| l.strip_prefix(key))
                .and_then(|l| l.strip_prefix(' '))
                .ok_or(malformed("a line is missing or out of order"))
        };
        let version = field(MAGIC)?;
        if version != VERSION.to_string() {
            return Err(CurrentError::Version(version.to_owned()));
        }
        let epoch = field("epoch")?;
        let epoch = (epoch.len() == 16)
            .then(|| u64::from_str_radix(epoch, 16).ok())
            .flatten()
            .ok_or(malformed("epoch is not 16 hex digits"))?;
        let file = field("file")?;
        if file != epoch_file_name(epoch) {
            return Err(malformed("file does not match epoch"));
        }
        let layout_version = field("layout")?.parse().map_err(|_| malformed("layout"))?;
        let size = field("size")?.parse().map_err(|_| malformed("size"))?;
        if lines.next().is_some() {
            return Err(malformed("trailing lines"));
        }
        Ok(Self {
            epoch,
            layout: layout_version,
            size,
        })
    }

    /// Whether this build can read the epoch file it names.
    pub fn readable(&self) -> bool {
        self.layout == layout::VERSION
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_names_the_file() {
        let c = Current {
            epoch: 0x1f2e_3d4c_5b6a_7988,
            layout: 1,
            size: 1_441_792,
        };
        let text = c.render();
        assert!(text.contains("file epoch-1f2e3d4c5b6a7988.shm\n"));
        assert_eq!(Current::parse(&text).unwrap(), c);
        assert!(c.readable());
        assert!(is_epoch_file_name(&c.file_name()));
    }

    #[test]
    fn a_pointer_naming_any_other_file_is_refused() {
        let c = Current {
            epoch: 1,
            layout: 1,
            size: 8,
        };
        for bad in [
            c.render()
                .replace("file epoch-0000000000000001.shm", "file ../../etc/shadow"),
            c.render().replace("epoch 0000000000000001", "epoch 1"),
            c.render()
                .replace("pf-sampler-current 1", "pf-sampler-current 2"),
            c.render() + "extra\n",
            c.render().replace("size 8", "size -1"),
        ] {
            assert!(Current::parse(&bad).is_err(), "{bad}");
        }
        assert!(!is_epoch_file_name("epoch-1.shm"));
        assert!(!is_epoch_file_name("epoch-000000000000000g.shm"));
    }
}
