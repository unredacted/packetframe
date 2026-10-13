//! The daemon's one allocator setting: glibc's fastbins off.
//!
//! glibc keeps a freed small chunk (128 bytes or less on 64-bit) that the
//! thread's tcache has no room for in a fastbin, unmerged, and merges
//! every fastbin chunk of the arena in one `malloc_consolidate` call when
//! a free of 64 KiB or more, or a request of 1 KiB or more, next comes
//! along. A FIB programmer walk that removes a full table (the
//! `InitiationComplete` GC, a `PeerDown`) frees millions of small chunks,
//! and the walk's own prefix list being dropped at its end is that free.
//! The walk gives the control-plane runtime back between chunks; the
//! consolidation then held one of its two workers in a single poll for
//! 1.058 s after a 1M-route GC and 553 ms after a `PeerDown` on the
//! reference gateway (`measure_full_table_walks`, hwtest build 379). With
//! fastbins off each free merges as it happens, and the same walks'
//! longest polls were 68 ms and 47 ms, the whole walks within about ±12%.
//!
//! The cost is the merging itself: a small free that misses the tcache
//! now coalesces with its neighbours, and a small request that misses it
//! is carved from the bins rather than popped from a fastbin. The heap's
//! layout changes with it, and so can the resident set; what was measured
//! of that, and what is owed, is in docs/runbooks/packetframe-fib.md
//! ("Force a route-source resync").
//!
//! `mallopt` rather than `GLIBC_TUNABLES=glibc.malloc.mxfast=0` in the
//! systemd unit: vpp-offload spawns VPP, which would inherit the
//! environment, and a setting chosen for packetframe's control plane is
//! not VPP's to take. `mallopt` changes this process only, and a child's
//! `exec` starts its allocator afresh.

/// What [`disable_fastbins`] did. Returned as well as logged, so the
/// measurement tests can print which allocator they measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fastbins {
    /// `mallopt(M_MXFAST, 0)` returned 1.
    Disabled,
    /// `GLIBC_TUNABLES` sets `glibc.malloc.mxfast`, to the value carried
    /// as written there. Fastbins are left as glibc set them from it.
    OperatorTunable(String),
    /// `GLIBC_TUNABLES` sets `glibc.malloc.mxfast` to a value glibc does not
    /// apply (not a number it reads, or above its largest fast size), so
    /// glibc kept its default fastbins and `mallopt(M_MXFAST, 0)` turned
    /// them off after all. Carries the value as written there.
    DisabledOverIgnoredTunable(String),
    /// `mallopt(M_MXFAST, 0)` returned 0. glibc refuses only a value
    /// above its maximum, so this is not expected; fastbins stay as they
    /// were.
    Refused,
    /// Not glibc's allocator, so there is nothing to set. The musl
    /// release builds link musl's (mallocng, what Rust's musl targets
    /// ship), which has no fastbins and defers no merging; a macOS dev
    /// build cannot run the daemon at all.
    NotGlibc,
}

/// Turn glibc's fastbins off for this process, unless `GLIBC_TUNABLES`
/// already sets them, and log the outcome once. Never fails: an
/// allocator that keeps its fastbins costs the stall described in the
/// [module docs](self), not correctness.
///
/// Call it first thing in `packetframe run`, while the process is still
/// one thread (glibc consolidates only the main arena before it lowers
/// the limit), and nowhere else in the CLI: the other subcommands are
/// short-lived and never walk a table.
pub fn disable_fastbins() -> Fastbins {
    let tunables = std::env::var_os(TUNABLES_ENV);
    let outcome = apply(tunables.as_ref().map(|t| t.to_string_lossy()).as_deref());
    outcome.log();
    outcome
}

const TUNABLES_ENV: &str = "GLIBC_TUNABLES";

impl Fastbins {
    fn log(&self) {
        match self {
            Fastbins::Disabled => tracing::info!(
                "malloc: fastbins off (mallopt M_MXFAST 0), so glibc merges freed memory as it \
                 goes, not in one long call at the end of a full-table walk; a \
                 glibc.malloc.mxfast in GLIBC_TUNABLES, when set, is kept instead"
            ),
            Fastbins::OperatorTunable(value) => tracing::info!(
                glibc_malloc_mxfast = %value,
                "malloc: GLIBC_TUNABLES sets glibc.malloc.mxfast, which is kept, and \
                 packetframe's own fastbins-off setting is skipped. With fastbins on, freeing \
                 a full-table walk's routes can hold a control-plane worker for about a second \
                 at 1M routes"
            ),
            Fastbins::DisabledOverIgnoredTunable(value) => tracing::warn!(
                glibc_malloc_mxfast = %value,
                max = MAX_FAST_SIZE,
                "malloc: GLIBC_TUNABLES sets glibc.malloc.mxfast to a value glibc ignores (not \
                 a number it reads, or above its largest fast size), so glibc kept its default \
                 fastbins; packetframe turned them off (mallopt M_MXFAST 0) instead. Fix or \
                 remove the tunable"
            ),
            Fastbins::Refused => tracing::warn!(
                "malloc: mallopt(M_MXFAST, 0) refused; fastbins stay on, so freeing a \
                 full-table walk's routes can hold a control-plane worker for about a second \
                 at 1M routes"
            ),
            Fastbins::NotGlibc => tracing::info!(
                "malloc: not glibc's allocator (musl's has no fastbins); nothing to set"
            ),
        }
    }
}

/// An operator's `glibc.malloc.mxfast` wins over the daemon's 0, as
/// `RUST_LOG` wins over the config's log level (crates/cli/src/logging.rs):
/// an explicit setting the daemon silently undid would make the mechanism
/// the operator reached for lie to them. It is also the one way back to
/// glibc's default without a rebuild, and how one build measures both
/// settings: `glibc.malloc.mxfast=128` is that default on 64-bit, so VPP
/// inheriting it changes nothing there. The price is that an operator can
/// bring the stall back; the journal line says when one has.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn apply(tunables: Option<&str>) -> Fastbins {
    let ignored = match tunables.and_then(mxfast_tunable) {
        Some(value) if glibc_applies_mxfast(value) => {
            return Fastbins::OperatorTunable(value.to_owned())
        }
        // glibc left its default in place, so keeping the operator's value
        // would keep nothing: apply ours, and say why.
        other => other,
    };
    // `libc` exposes `M_MXFAST` (glibc's malloc.h, 1) and `mallopt` for
    // every linux-gnu target.
    // SAFETY: two ints in, an int out; glibc changes only its own malloc
    // state, under the main arena's lock.
    match unsafe { libc::mallopt(libc::M_MXFAST, 0) } {
        1 => match ignored {
            Some(value) => Fastbins::DisabledOverIgnoredTunable(value.to_owned()),
            None => Fastbins::Disabled,
        },
        _ => Fastbins::Refused,
    }
}

/// glibc's `MAX_FAST_SIZE` (malloc.c): `80 * sizeof(size_t) / 4`, 160 on
/// 64-bit. `do_set_mxfast` applies a `glibc.malloc.mxfast` only up to it
/// and otherwise leaves the default.
const MAX_FAST_SIZE: u64 = (80 * std::mem::size_of::<usize>() / 4) as u64;

/// Whether glibc applies this `glibc.malloc.mxfast` value. Tunables are
/// read as `_dl_strtoul` reads them (decimal, `0x` hex, a leading `0`
/// octal) and only when the whole string is a number; glibc ignores a
/// value it cannot read, and `do_set_mxfast` one above [`MAX_FAST_SIZE`].
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn glibc_applies_mxfast(value: &str) -> bool {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else if value.len() > 1 && value.starts_with('0') {
        u64::from_str_radix(&value[1..], 8).ok()
    } else {
        value.parse::<u64>().ok()
    };
    parsed.is_some_and(|v| v <= MAX_FAST_SIZE)
}

/// musl's allocator, or no Linux at all: see [`Fastbins::NotGlibc`].
/// `GLIBC_TUNABLES` means nothing to either.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn apply(_tunables: Option<&str>) -> Fastbins {
    Fastbins::NotGlibc
}

/// The value `GLIBC_TUNABLES` gives `glibc.malloc.mxfast`: `name=value`
/// pairs separated by `:`, the last one naming the tunable standing, as
/// in glibc. An entry without `=` names nothing.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn mxfast_tunable(tunables: &str) -> Option<&str> {
    tunables
        .rsplit(':')
        .filter_map(|entry| entry.split_once('='))
        .find(|(name, _)| *name == "glibc.malloc.mxfast")
        .map(|(_, value)| value)
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;

    /// The daemon's own call, without an operator tunable: glibc accepts
    /// `M_MXFAST` 0 (mallopt returns 1). Changes this test binary's
    /// allocator, which nothing here depends on.
    #[test]
    fn mallopt_accepts_mxfast_zero() {
        assert_eq!(apply(None), Fastbins::Disabled);
        assert_eq!(
            apply(Some("glibc.malloc.tcache_count=0")),
            Fastbins::Disabled
        );
    }

    #[test]
    fn an_mxfast_glibc_ignores_is_not_kept() {
        for bad in ["999999", "161", "abc", "", "0x", "12k", "-1", "0x1000"] {
            assert_eq!(
                apply(Some(&format!("glibc.malloc.mxfast={bad}"))),
                Fastbins::DisabledOverIgnoredTunable(bad.into()),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn glibc_reads_mxfast_as_its_tunables_parser_does() {
        for ok in ["0", "64", "128", "160", "0x80", "0XA0", "0200", "00"] {
            assert!(glibc_applies_mxfast(ok), "{ok:?} should apply");
        }
        for bad in ["161", "0xA1", "0241", "999999", "abc", "", "0x", "09", "1 "] {
            assert!(!glibc_applies_mxfast(bad), "{bad:?} should be ignored");
        }
    }

    #[test]
    fn an_operator_mxfast_is_kept() {
        assert_eq!(
            apply(Some("glibc.malloc.mxfast=128")),
            Fastbins::OperatorTunable("128".into())
        );
    }

    #[test]
    fn mxfast_is_read_as_glibc_reads_tunables() {
        assert_eq!(mxfast_tunable("glibc.malloc.mxfast=0"), Some("0"));
        assert_eq!(
            mxfast_tunable("glibc.malloc.tcache_count=0:glibc.malloc.mxfast=64"),
            Some("64")
        );
        // The last one stands.
        assert_eq!(
            mxfast_tunable("glibc.malloc.mxfast=0:glibc.malloc.mxfast=128"),
            Some("128")
        );
        // An entry without `=` names nothing, and does not swallow the
        // next one.
        assert_eq!(
            mxfast_tunable("glibc.malloc.mxfast:glibc.malloc.mxfast=32"),
            Some("32")
        );
        assert_eq!(mxfast_tunable("glibc.malloc.mxfast"), None);
        assert_eq!(mxfast_tunable("glibc.malloc.mxfastx=1"), None);
        assert_eq!(mxfast_tunable("glibc.malloc.trim_threshold=131072"), None);
        assert_eq!(mxfast_tunable(""), None);
    }
}
