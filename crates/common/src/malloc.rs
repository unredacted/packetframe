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
//! of that is in docs/runbooks/packetframe-fib.md
//! ("Force a route-source resync").
//!
//! `mallopt` rather than `GLIBC_TUNABLES=glibc.malloc.mxfast=0` in the
//! systemd unit: vpp-offload spawns VPP, which would inherit the
//! environment, and a setting chosen for packetframe's control plane is
//! not VPP's to take. `mallopt` changes this process only, and a child's
//! `exec` starts its allocator afresh.
//!
//! **`GLIBC_TUNABLES` is not interpreted.** Whether glibc applied a
//! `glibc.malloc.mxfast` there depends on its tunables parser in detail
//! (a sign, whitespace, a malformed entry elsewhere that voids the whole
//! string, a value above its bound, a release with no fastbins at all),
//! and guessing at that from outside would have the start-up line claim a
//! setting glibc had dropped. So the daemon always applies its own, which
//! overrides such a tunable (a `mallopt` after start wins), and the opt-out
//! is a variable of its own: [`KEEP_ENV`]. The daemon only notes whether
//! the variable names `glibc.malloc.mxfast`, so the start-up line can say
//! it was overridden.

/// Set to `on` in the daemon's environment (a systemd drop-in) to run
/// with glibc's default fastbins: the way back to glibc's default without
/// a rebuild, and how one build measures both settings. The daemon then
/// sets glibc's default limit itself ([`DEFAULT_MXFAST`]), so a
/// `glibc.malloc.mxfast` left in `GLIBC_TUNABLES` cannot change what is
/// measured. Any other value, or none, leaves the daemon's setting in
/// force.
pub const KEEP_ENV: &str = "PACKETFRAME_MALLOC_FASTBINS";

/// The first glibc release without fastbins: 2.43 removed them, and
/// `M_MXFAST` became a no-op there.
/// glibc's `DEFAULT_MXFAST` (malloc.c): `64 * sizeof(size_t) / 4`, 128 on
/// 64-bit. What [`KEEP_ENV`] restores.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const DEFAULT_MXFAST: libc::c_int = (64 * std::mem::size_of::<usize>() / 4) as libc::c_int;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const FIRST_GLIBC_WITHOUT_FASTBINS: (u32, u32) = (2, 43);

/// What [`disable_fastbins`] did. Returned as well as logged, so the
/// measurement tests can print which allocator they measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fastbins {
    /// `mallopt(M_MXFAST, 0)` returned 1. Carries whether `GLIBC_TUNABLES`
    /// named `glibc.malloc.mxfast`, which this overrides.
    Disabled { overrode_tunable: bool },
    /// [`KEEP_ENV`] is `on`, and `mallopt(M_MXFAST, DEFAULT_MXFAST)`
    /// returned 1: glibc's default fastbins, whatever `GLIBC_TUNABLES`
    /// said.
    Kept,
    /// `mallopt(M_MXFAST, …)` returned 0. glibc refuses only a value above
    /// its maximum, which neither 0 nor its own default is, so this is not
    /// expected; fastbins stay as they were.
    Refused,
    /// This glibc has no fastbins (2.43 and later), so there is nothing to
    /// set. Carries the version glibc reports.
    NoFastbins(String),
    /// Not glibc's allocator, so there is nothing to set. The musl release
    /// builds link musl's (mallocng, what Rust's musl targets ship), which
    /// has no fastbins and defers no merging; a macOS dev build cannot run
    /// the daemon at all.
    NotGlibc,
}

/// Turn glibc's fastbins off for this process, unless [`KEEP_ENV`] says to
/// keep them, and log the outcome once. Never fails: an allocator that
/// keeps its fastbins costs the stall described in the [module
/// docs](self), not correctness.
///
/// Call it first thing in `packetframe run`, while the process is still
/// one thread (glibc consolidates only the main arena before it lowers
/// the limit), and nowhere else in the CLI: the other subcommands are
/// short-lived and never walk a table.
pub fn disable_fastbins() -> Fastbins {
    let keep = std::env::var_os(KEEP_ENV).is_some_and(|v| v == "on");
    let tunable = std::env::var_os("GLIBC_TUNABLES")
        .is_some_and(|t| t.to_string_lossy().contains("glibc.malloc.mxfast"));
    let outcome = apply(keep, tunable, glibc_version());
    outcome.log();
    outcome
}

impl Fastbins {
    fn log(&self) {
        match self {
            Fastbins::Disabled { overrode_tunable } => tracing::info!(
                overrode_glibc_tunable = *overrode_tunable,
                "malloc: fastbins off (mallopt M_MXFAST 0), so glibc merges freed memory as it \
                 goes, not in one long call at the end of a full-table walk; {KEEP_ENV}=on \
                 keeps glibc's fastbins, and a glibc.malloc.mxfast in GLIBC_TUNABLES is \
                 overridden"
            ),
            Fastbins::Kept => tracing::info!(
                "malloc: {KEEP_ENV}=on, so fastbins are at glibc's default (mallopt M_MXFAST \
                 set to it, overriding any glibc.malloc.mxfast). Freeing a full-table walk's \
                 routes can then hold a control-plane worker for about a second at 1M routes"
            ),
            Fastbins::Refused => tracing::warn!(
                "malloc: mallopt(M_MXFAST, 0) refused; fastbins stay on, so freeing a \
                 full-table walk's routes can hold a control-plane worker for about a second \
                 at 1M routes"
            ),
            Fastbins::NoFastbins(version) => tracing::info!(
                glibc = %version,
                "malloc: this glibc has no fastbins (removed in 2.43); nothing to set"
            ),
            Fastbins::NotGlibc => tracing::info!(
                "malloc: not glibc's allocator (musl's has no fastbins); nothing to set"
            ),
        }
    }
}

/// The decision, apart from the environment and the running glibc so it
/// can be tested. A glibc version that cannot be read is taken to have
/// fastbins: every release before 2.43 does, and `mallopt` is harmless
/// where they are gone.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn apply(keep: bool, tunable: bool, glibc: Option<(String, (u32, u32))>) -> Fastbins {
    if let Some((version, parsed)) = glibc {
        if parsed >= FIRST_GLIBC_WITHOUT_FASTBINS {
            return Fastbins::NoFastbins(version);
        }
    }
    // `libc` exposes `M_MXFAST` (glibc's malloc.h, 1) and `mallopt` for
    // every linux-gnu target. Set either way, so the outcome never rests on
    // what a GLIBC_TUNABLES entry did or did not do at start.
    let limit = if keep { DEFAULT_MXFAST } else { 0 };
    // SAFETY: two ints in, an int out; glibc changes only its own malloc
    // state, under the main arena's lock.
    match (unsafe { libc::mallopt(libc::M_MXFAST, limit) }, keep) {
        (1, true) => Fastbins::Kept,
        (1, false) => Fastbins::Disabled {
            overrode_tunable: tunable,
        },
        _ => Fastbins::Refused,
    }
}

/// musl's allocator, or no Linux at all: see [`Fastbins::NotGlibc`].
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn apply(_keep: bool, _tunable: bool, _glibc: Option<(String, (u32, u32))>) -> Fastbins {
    Fastbins::NotGlibc
}

/// The running glibc's version, as `gnu_get_libc_version` reports it, and
/// its major and minor parsed. `None` off glibc or when it cannot be read.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn glibc_version() -> Option<(String, (u32, u32))> {
    // SAFETY: glibc returns a pointer to a static NUL-terminated string.
    let raw = unsafe { libc::gnu_get_libc_version() };
    if raw.is_null() {
        return None;
    }
    let version = unsafe { std::ffi::CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    let parsed = parse_version(&version)?;
    Some((version, parsed))
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn glibc_version() -> Option<(String, (u32, u32))> {
    None
}

/// `major.minor[.anything]` as two numbers.
#[cfg_attr(not(all(target_os = "linux", target_env = "gnu")), allow(dead_code))]
fn parse_version(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_versions_parse_to_major_and_minor() {
        assert_eq!(parse_version("2.31"), Some((2, 31)));
        assert_eq!(parse_version("2.43"), Some((2, 43)));
        assert_eq!(parse_version("2.43.9000"), Some((2, 43)));
        assert_eq!(parse_version("2"), None);
        assert_eq!(parse_version("x.y"), None);
        assert_eq!(parse_version(""), None);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn fastbins_go_off_unless_kept_or_absent() {
        let old = || Some(("2.31".to_string(), (2, 31)));
        assert_eq!(
            apply(false, false, old()),
            Fastbins::Disabled {
                overrode_tunable: false
            },
            "mallopt(M_MXFAST, 0) returns 1"
        );
        assert_eq!(
            apply(false, true, old()),
            Fastbins::Disabled {
                overrode_tunable: true
            }
        );
        assert_eq!(
            apply(true, true, old()),
            Fastbins::Kept,
            "mallopt(M_MXFAST, DEFAULT_MXFAST) returns 1"
        );
        assert_eq!(apply(true, false, old()), Fastbins::Kept);
        // Leave the process at the daemon's setting for the tests after.
        assert!(matches!(
            apply(false, false, old()),
            Fastbins::Disabled { .. }
        ));
        assert_eq!(
            apply(false, false, Some(("2.43".to_string(), (2, 43)))),
            Fastbins::NoFastbins("2.43".into())
        );
        assert_eq!(
            apply(true, false, Some(("2.44".to_string(), (2, 44)))),
            Fastbins::NoFastbins("2.44".into()),
            "nothing to keep either"
        );
        assert_eq!(
            apply(false, false, None),
            Fastbins::Disabled {
                overrode_tunable: false
            },
            "an unreadable version is taken to have fastbins"
        );
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn the_running_glibc_reports_a_version() {
        assert!(glibc_version().is_some(), "gnu_get_libc_version");
    }
}
