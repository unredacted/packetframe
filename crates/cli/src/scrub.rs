//! Making text safe to print at an operator's terminal.
//!
//! Every string this CLI prints that did not originate in this process
//! is untrusted for terminal purposes. Not because anything here is
//! adversarial, but because the sources are: `strerror` text from ioctls,
//! VPP and ethtool error strings, module names read back out of on-disk
//! JSON, config parse errors quoting the file they failed on. An ANSI
//! escape reaching a TTY through any of those corrupts the display of a
//! command an operator ran to find out what is wrong.
//!
//! **One place decides what a control character is.** This started as a
//! pair of private helpers in `loader.rs` covering the health surface
//! only; the reconfigure marker had its own copy first. Two copies of
//! this rule is exactly how one of them ends up not being applied.

/// Replace control characters, keeping tab and newline.
///
/// For text going into a **line-oriented file** — the reconfigure marker
/// — where the newline is the record separator and removing it would
/// corrupt the format this is protecting.
pub fn scrub_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// The same scrub, for text going **straight to a terminal**.
///
/// Built on [`scrub_control_chars`] rather than beside it, so what counts
/// as a control character is decided once. What differs is tab and
/// newline: a terminal must not keep them, because a `\n` inside a
/// message can **forge a row**. A subsystem message ending
/// `"\n  vpp-offload: healthy"` prints an extra module line that no
/// module reported, and an operator has no way to tell it apart from a
/// real one.
pub fn scrub_for_terminal(s: &str) -> String {
    scrub_control_chars(s).replace(['\n', '\t'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_do_not_survive_either_scrub() {
        let hostile = "vpp said \x1b[2J\x1b[1;31mBOOM\x07";
        assert!(!scrub_control_chars(hostile).contains('\x1b'));
        assert!(!scrub_for_terminal(hostile).contains('\x1b'));
        assert!(!scrub_for_terminal(hostile).contains('\x07'));
    }

    /// The whole reason the terminal variant exists.
    #[test]
    fn a_newline_cannot_forge_a_row_at_a_terminal() {
        let forged = "ok\n  vpp-offload: healthy";
        assert!(
            scrub_control_chars(forged).contains('\n'),
            "the marker file keeps newlines — they are its record separator"
        );
        assert!(
            !scrub_for_terminal(forged).contains('\n'),
            "a terminal must not, or a message can print a line no module reported"
        );
    }

    /// Ordinary text — including non-ASCII — passes through untouched.
    /// A scrub that mangles a legitimate error message makes the output
    /// it protects less usable, which is its own kind of failure.
    #[test]
    fn ordinary_text_is_unchanged() {
        for s in [
            "Operation not supported (os error 95)",
            "inserting ntuple rule at loc 15",
            "/run/packetframe/vpp/api.sock",
            "café — ünïcode is not a control character",
        ] {
            assert_eq!(scrub_for_terminal(s), s);
            assert_eq!(scrub_control_chars(s), s);
        }
    }
}
