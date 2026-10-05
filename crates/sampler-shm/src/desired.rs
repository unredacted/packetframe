//! `desired.conf`: PacketFrame's configuration for the plugin.
//!
//! One writer (PacketFrame, holding `desired.lock`) replaces the file by
//! rename, never in place; the plugin rereads it when its inode, mtime or
//! size changes and never modifies it. Line-based and strict, so a file a
//! human edited by hand is either exactly right or refused with a line
//! number:
//!
//! ```text
//! pf-sampler-desired 1
//! generation 7
//! rate 1000
//! header-bytes 128
//! classes ingress
//! interface octeon1/0
//! interface octeon0/0
//! checksum 5c1b8e0f2a3d4c6e
//! ```
//!
//! Interfaces are VPP interface names: PacketFrame creates them after VPP
//! starts, so the plugin resolves names, not indices. The checksum is
//! FNV-1a 64 over every byte before the `checksum` line. `#` lines are
//! comments.

use crate::layout::{HEADER_CAPACITY_MAX, MAX_INTERFACES};
use crate::{fnv1a64, valid_interface_name, Class, Classes};

pub const VERSION: u32 = 1;
const MAGIC: &str = "pf-sampler-desired";
pub const MAX_RATE: u32 = 1 << 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desired {
    /// Increases with every change PacketFrame makes; never 0.
    pub generation: u64,
    /// 1-in-N.
    pub rate: u32,
    /// Leading packet bytes to copy into each sample.
    pub header_bytes: u32,
    pub classes: Classes,
    /// VPP interface names, unique.
    pub interfaces: Vec<String>,
}

/// Why a file was refused. [`Self::code`] is what the plugin reports in
/// its status (`rejected_reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Version,
    Checksum,
    Syntax,
    Range,
    Duplicate,
    TooManyInterfaces,
    Missing,
    /// Valid here, but beyond what this plugin's epoch file can hold
    /// (header bytes) or what it implements (a class).
    Unsupported,
}

impl ErrorKind {
    pub fn code(self) -> u64 {
        match self {
            ErrorKind::Version => 1,
            ErrorKind::Checksum => 2,
            ErrorKind::Syntax => 3,
            ErrorKind::Range => 4,
            ErrorKind::Duplicate => 5,
            ErrorKind::TooManyInterfaces => 6,
            ErrorKind::Missing => 7,
            ErrorKind::Unsupported => 8,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => ErrorKind::Version,
            2 => ErrorKind::Checksum,
            3 => ErrorKind::Syntax,
            4 => ErrorKind::Range,
            5 => ErrorKind::Duplicate,
            6 => ErrorKind::TooManyInterfaces,
            7 => ErrorKind::Missing,
            8 => ErrorKind::Unsupported,
            _ => return None,
        })
    }

    pub fn describe(self) -> &'static str {
        match self {
            ErrorKind::Version => "unknown format version",
            ErrorKind::Checksum => "checksum mismatch",
            ErrorKind::Syntax => "syntax error",
            ErrorKind::Range => "value out of range",
            ErrorKind::Duplicate => "key or interface given twice",
            ErrorKind::TooManyInterfaces => "more than 64 interfaces",
            ErrorKind::Missing => "required key missing",
            ErrorKind::Unsupported => "not supported by this plugin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("desired.conf line {line}: {}: {detail}", .kind.describe())]
pub struct Error {
    pub kind: ErrorKind,
    /// 1-based; 0 when the error is about the file as a whole.
    pub line: u64,
    pub detail: String,
}

fn err(kind: ErrorKind, line: usize, detail: impl Into<String>) -> Error {
    Error {
        kind,
        line: line as u64,
        detail: detail.into(),
    }
}

impl Desired {
    /// The file's contents, checksum included.
    pub fn render(&self) -> String {
        let mut s = format!(
            "# written by packetframe; replaced atomically, never edited in place\n\
             {MAGIC} {VERSION}\n\
             generation {}\nrate {}\nheader-bytes {}\nclasses",
            self.generation, self.rate, self.header_bytes
        );
        for c in Class::ALL {
            if self.classes & c.bit() != 0 {
                s.push(' ');
                s.push_str(c.name());
            }
        }
        s.push('\n');
        for i in &self.interfaces {
            s.push_str("interface ");
            s.push_str(i);
            s.push('\n');
        }
        let sum = fnv1a64(s.as_bytes());
        s.push_str(&format!("checksum {sum:016x}\n"));
        s
    }

    /// Parses and validates a file. Everything except what depends on the
    /// running plugin ([`Self::check_supported`]) is checked here.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let Some(at) = text.rfind("checksum ") else {
            return Err(err(ErrorKind::Missing, 0, "no checksum line"));
        };
        if at != 0 && text.as_bytes()[at - 1] != b'\n' {
            return Err(err(
                ErrorKind::Syntax,
                0,
                "checksum is not on a line of its own",
            ));
        }
        let (body, sum_line) = text.split_at(at);
        let sum_line = sum_line.strip_suffix('\n').unwrap_or(sum_line);
        let sum_lineno = body.lines().count() + 1;
        let stated = sum_line
            .strip_prefix("checksum ")
            .filter(|h| h.len() == 16)
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .ok_or_else(|| {
                err(
                    ErrorKind::Syntax,
                    sum_lineno,
                    "checksum is not 16 hex digits",
                )
            })?;
        if stated != fnv1a64(body.as_bytes()) {
            return Err(err(
                ErrorKind::Checksum,
                sum_lineno,
                "the file was changed after writing",
            ));
        }

        let mut version_seen = false;
        let (mut generation, mut rate, mut header_bytes, mut classes) = (None, None, None, None);
        let mut interfaces: Vec<String> = Vec::new();
        for (i, line) in body.lines().enumerate() {
            let n = i + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut words = line.split(' ');
            let key = words.next().unwrap_or_default();
            let args: Vec<&str> = words.collect();
            if args.iter().any(|a| a.is_empty()) {
                return Err(err(
                    ErrorKind::Syntax,
                    n,
                    "words are separated by exactly one space",
                ));
            }
            if !version_seen {
                if key != MAGIC || args.len() != 1 {
                    return Err(err(
                        ErrorKind::Syntax,
                        n,
                        format!("expected `{MAGIC} {VERSION}`"),
                    ));
                }
                if args[0] != VERSION.to_string() {
                    return Err(err(ErrorKind::Version, n, format!("version {}", args[0])));
                }
                version_seen = true;
                continue;
            }
            let one = || -> Result<&str, Error> {
                match args.as_slice() {
                    [a] => Ok(a),
                    _ => Err(err(
                        ErrorKind::Syntax,
                        n,
                        format!("`{key}` takes one value"),
                    )),
                }
            };
            let num = |max: u64| -> Result<u64, Error> {
                let v: u64 = one()?
                    .parse()
                    .map_err(|_| err(ErrorKind::Syntax, n, format!("`{key}` is not a number")))?;
                if v > max {
                    return Err(err(ErrorKind::Range, n, format!("`{key}` above {max}")));
                }
                Ok(v)
            };
            let once = |slot: &Option<u64>| {
                if slot.is_some() {
                    Err(err(ErrorKind::Duplicate, n, format!("`{key}` given twice")))
                } else {
                    Ok(())
                }
            };
            match key {
                "generation" => {
                    once(&generation)?;
                    let v = num(u64::MAX)?;
                    if v == 0 {
                        return Err(err(ErrorKind::Range, n, "generation 0"));
                    }
                    generation = Some(v);
                }
                "rate" => {
                    once(&rate)?;
                    let v = num(u64::from(MAX_RATE))?;
                    if v == 0 {
                        return Err(err(ErrorKind::Range, n, "rate 0"));
                    }
                    rate = Some(v);
                }
                "header-bytes" => {
                    once(&header_bytes)?;
                    header_bytes = Some(num(HEADER_CAPACITY_MAX as u64)?);
                }
                "classes" => {
                    once(&classes)?;
                    if args.is_empty() {
                        return Err(err(ErrorKind::Range, n, "no classes"));
                    }
                    let mut set = 0;
                    for a in &args {
                        let c =
                            Class::ALL
                                .into_iter()
                                .find(|c| c.name() == *a)
                                .ok_or_else(|| {
                                    err(ErrorKind::Syntax, n, format!("unknown class `{a}`"))
                                })?;
                        if set & c.bit() != 0 {
                            return Err(err(ErrorKind::Duplicate, n, format!("class `{a}` twice")));
                        }
                        set |= c.bit();
                    }
                    classes = Some(set);
                }
                "interface" => {
                    let name = one()?;
                    if !valid_interface_name(name) {
                        return Err(err(
                            ErrorKind::Range,
                            n,
                            format!("bad interface name `{name}`"),
                        ));
                    }
                    if interfaces.iter().any(|i| i == name) {
                        return Err(err(
                            ErrorKind::Duplicate,
                            n,
                            format!("interface `{name}` twice"),
                        ));
                    }
                    if interfaces.len() == MAX_INTERFACES {
                        return Err(err(ErrorKind::TooManyInterfaces, n, name));
                    }
                    interfaces.push(name.to_owned());
                }
                _ => return Err(err(ErrorKind::Syntax, n, format!("unknown key `{key}`"))),
            }
        }
        if !version_seen {
            return Err(err(ErrorKind::Missing, 0, "no version line"));
        }
        let need = |v: Option<u64>, what: &str| {
            v.ok_or_else(|| err(ErrorKind::Missing, 0, what.to_owned()))
        };
        Ok(Desired {
            generation: need(generation, "generation")?,
            rate: need(rate, "rate")? as u32,
            header_bytes: need(header_bytes, "header-bytes")? as u32,
            classes: need(classes, "classes")?,
            interfaces,
        })
    }

    /// What the running plugin can do: copy at most `header_capacity`
    /// bytes, and sample the `implemented` classes.
    pub fn check_supported(
        &self,
        header_capacity: usize,
        implemented: Classes,
    ) -> Result<(), Error> {
        if self.header_bytes as usize > header_capacity {
            return Err(err(
                ErrorKind::Unsupported,
                0,
                format!(
                    "header-bytes {} above this epoch's {header_capacity}",
                    self.header_bytes
                ),
            ));
        }
        if self.classes & !implemented != 0 {
            return Err(err(
                ErrorKind::Unsupported,
                0,
                "a class this plugin does not sample",
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    fn sample() -> Desired {
        Desired {
            generation: 7,
            rate: 1000,
            header_bytes: 128,
            classes: Class::Ingress.bit() | Class::Drop.bit(),
            interfaces: vec!["octeon1/0".into(), "octeon0/0".into()],
        }
    }

    /// Re-signs a hand-edited body, so a test reaches the check after the
    /// checksum.
    fn signed(body: &str) -> String {
        format!("{body}checksum {:016x}\n", fnv1a64(body.as_bytes()))
    }

    fn kind(text: &str) -> (ErrorKind, u64) {
        let e = Desired::parse(text).unwrap_err();
        (e.kind, e.line)
    }

    #[test]
    fn rendered_files_parse_back() {
        let d = sample();
        assert_eq!(Desired::parse(&d.render()).unwrap(), d);
        let empty = Desired {
            interfaces: vec![],
            ..sample()
        };
        assert_eq!(Desired::parse(&empty.render()).unwrap(), empty);
    }

    #[test]
    fn any_change_after_writing_fails_the_checksum() {
        let text = sample().render().replace("rate 1000", "rate 1001");
        assert_eq!(kind(&text).0, ErrorKind::Checksum);
        let truncated = &sample().render()[..40];
        assert_eq!(kind(truncated).0, ErrorKind::Missing);
    }

    #[test]
    fn strict_parsing_names_the_line() {
        let head = "pf-sampler-desired 1\n";
        let rest = "rate 1000\nheader-bytes 128\nclasses ingress\n";
        assert_eq!(
            kind(&signed("pf-sampler-desired 2\n")),
            (ErrorKind::Version, 1)
        );
        assert_eq!(
            kind(&signed(&format!("{head}generation 0\n{rest}"))),
            (ErrorKind::Range, 2)
        );
        assert_eq!(
            kind(&signed(&format!("{head}generation 1\nrate 0\n"))),
            (ErrorKind::Range, 3)
        );
        assert_eq!(
            kind(&signed(&format!("{head}generation 1\n{rest}rate 5\n"))),
            (ErrorKind::Duplicate, 6)
        );
        assert_eq!(
            kind(&signed(&format!("{head}generation 1\n{rest}colour blue\n"))),
            (ErrorKind::Syntax, 6)
        );
        assert_eq!(
            kind(&signed(&format!(
                "{head}generation 1\n{rest}interface a\ninterface a\n"
            ))),
            (ErrorKind::Duplicate, 7)
        );
        assert_eq!(
            kind(&signed(&format!("{head}generation  1\n{rest}"))),
            (ErrorKind::Syntax, 2)
        );
        assert_eq!(
            kind(&signed(&format!("{head}{rest}"))),
            (ErrorKind::Missing, 0)
        );
        assert_eq!(
            kind(&signed(&format!(
                "{head}generation 1\nrate 1\nheader-bytes 513\n"
            ))),
            (ErrorKind::Range, 4)
        );
        assert_eq!(
            kind(&signed(&format!(
                "{head}generation 1\nclasses ingress sideways\n"
            ))),
            (ErrorKind::Syntax, 3)
        );
        let many: String = (0..=MAX_INTERFACES)
            .map(|i| format!("interface p{i}\n"))
            .collect();
        assert_eq!(
            kind(&signed(&format!("{head}generation 1\n{rest}{many}"))).0,
            ErrorKind::TooManyInterfaces
        );
        assert_eq!(kind("generation 1\n").0, ErrorKind::Missing, "no checksum");
    }

    #[test]
    fn support_depends_on_the_running_plugin() {
        let d = sample();
        assert!(d
            .check_supported(128, Class::Ingress.bit() | Class::Drop.bit())
            .is_ok());
        assert_eq!(
            d.check_supported(64, u64::MAX).unwrap_err().kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            d.check_supported(256, Class::Ingress.bit())
                .unwrap_err()
                .kind,
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn error_codes_round_trip() {
        for code in 1..=8 {
            assert_eq!(ErrorKind::from_code(code).unwrap().code(), code);
        }
        assert_eq!(ErrorKind::from_code(0), None);
    }
}
