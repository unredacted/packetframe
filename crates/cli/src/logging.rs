//! Process log filter: installed at startup, updated from
//! `global.log-level` (SPEC.md §6) once the config has been read.
//!
//! The subscriber has to exist before the config does — a config parse
//! failure is itself something we log — so the filter cannot simply be
//! built from `global.log_level`. Instead it is installed *reloadable*
//! at the built-in default, and [`apply_config_level`] swaps it as soon
//! as a config is in hand: at startup in `loader::run`, and again on
//! every accepted SIGHUP, which is what makes the level hot-reloadable.
//!
//! Precedence is env-beats-file. `RUST_LOG`, when set and parseable,
//! pins the filter for the life of the process and the config directive
//! is ignored (said once, out loud — a silently discarded directive is
//! the bug this module exists to fix). That keeps the documented
//! per-module escape hatches working, including the one for
//! bgpkit-parser noise below, which no whole-process level can express.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use packetframe_common::config::LogLevel;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{reload, EnvFilter, Registry};

/// One upstream noise source, suppressed in every filter we build from
/// a level. `bgpkit_parser::parser::bgp::messages` emits a `WARN seeing
/// strange one-byte NLRI field` whenever a BGP UPDATE arrives with a
/// 1-byte NLRI section, which is the valid wire encoding of a default
/// route (`0.0.0.0/0`: prefix-length byte = 0, zero prefix bytes
/// follow). bgpkit-parser conservatively treats it as malformed and
/// skips. For our use case (bird with `accept-default: false`, no
/// defaults in the RIB) the warning fires once per session when bird
/// emits a withdraw of the default and is otherwise misleading noise.
/// Demoting that one module to `error` keeps genuine bgpkit-parser
/// failures visible without the cosmetic line.
///
/// Operators who want the raw parser warnings back set
/// `RUST_LOG=info,bgpkit_parser::parser::bgp::messages=warn`, which
/// takes the whole filter with it — see the module docs on precedence.
const BGPKIT_NLRI_NOISE: &str = "bgpkit_parser::parser::bgp::messages=error";

/// Second upstream noise source, same treatment. `netlink_proto` emits
/// `WARN netlink socket buffer full` once per dropped datagram on
/// ENOBUFS — unbounded and identical: the shadow repro (2026-08-13)
/// logged 25 copies in a quarter second while six ports came up under
/// VPP churn. The event it describes is survivable by design: the
/// neighbour resolver seeds from dumps and the kernel's own ARP
/// lifecycle re-announces entries as they churn REACHABLE/STALE, so a
/// dropped notification heals; the resolver's periodic stats line is
/// the ongoing health signal. One copy would be worth keeping — a copy
/// per datagram buries the WARNs that matter, which during that repro
/// included the teardown reasons this build exists to surface.
///
/// Re-enable when debugging netlink loss:
/// `RUST_LOG=info,netlink_proto=warn`.
const NETLINK_ENOBUFS_NOISE: &str = "netlink_proto=error";

/// The filter spec for a config-supplied level.
fn spec_for(level: LogLevel) -> String {
    format!(
        "{},{BGPKIT_NLRI_NOISE},{NETLINK_ENOBUFS_NOISE}",
        level.as_str()
    )
}

/// Where the live filter came from, which decides whether the config
/// gets to touch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterSource {
    /// `RUST_LOG` was set and parsed. The config never overrides it.
    Env,
    /// No usable `RUST_LOG`; `global.log-level` owns the filter.
    Config,
}

/// A resolved startup filter plus how it was chosen.
struct Resolved {
    filter: EnvFilter,
    source: FilterSource,
    /// Deferred complaint about a malformed `RUST_LOG`. Resolution runs
    /// before the subscriber exists, so it cannot be logged in place.
    warning: Option<String>,
}

/// Pick the startup filter from `RUST_LOG` (already read, so this is
/// testable without touching the process environment) falling back to
/// `default_level` — which is [`LogLevel::Info`] in practice, since the
/// real config level is only known later.
///
/// A `RUST_LOG` that is set but does not parse falls back rather than
/// aborting startup, and leaves the config in charge: a typo in a
/// systemd drop-in should not also cost the operator their config's
/// level, and it should not be silent either.
fn resolve(env: Option<String>, default_level: LogLevel) -> Resolved {
    match env {
        Some(spec) => match EnvFilter::try_new(&spec) {
            Ok(filter) => Resolved {
                filter,
                source: FilterSource::Env,
                warning: None,
            },
            Err(e) => Resolved {
                filter: EnvFilter::new(spec_for(default_level)),
                source: FilterSource::Config,
                warning: Some(format!(
                    "RUST_LOG=`{spec}` did not parse ({e}); \
                     falling back to the config's log-level"
                )),
            },
        },
        None => Resolved {
            filter: EnvFilter::new(spec_for(default_level)),
            source: FilterSource::Config,
            warning: None,
        },
    }
}

/// The live filter's reload handle plus the precedence decision.
struct LogControl {
    handle: reload::Handle<EnvFilter, Registry>,
    source: FilterSource,
    /// Level currently installed from the config. Guards against
    /// rebuilding the callsite interest cache on every SIGHUP that
    /// leaves `log-level` alone, which is nearly all of them.
    applied: Mutex<LogLevel>,
    /// Whether the "your config directive is being ignored" notice has
    /// been emitted. Once per process is enough; SIGHUP would otherwise
    /// repeat it forever.
    env_notice_said: AtomicBool,
}

impl LogControl {
    fn new(
        handle: reload::Handle<EnvFilter, Registry>,
        source: FilterSource,
        installed: LogLevel,
    ) -> Self {
        Self {
            handle,
            source,
            applied: Mutex::new(installed),
            env_notice_said: AtomicBool::new(false),
        }
    }

    fn apply(&self, level: LogLevel) {
        if self.source == FilterSource::Env {
            if !self.env_notice_said.swap(true, Ordering::Relaxed) {
                // "for this process" is the whole of it: the source is
                // decided in `init` and the environment is never read
                // again, so clearing RUST_LOG needs a restart. Saying
                // "reload" here would be this module's own defect —
                // pointing an operator at an action that changes
                // nothing — one layer up from the one it fixes.
                tracing::info!(
                    config_log_level = level.as_str(),
                    "RUST_LOG is set; the config's log-level is ignored for this process \
                     (env beats file). Overriding it needs a narrower RUST_LOG, not this \
                     directive; handing the level back to the config needs RUST_LOG cleared \
                     and the daemon restarted."
                );
            }
            return;
        }

        // Poisoning here means a previous caller panicked mid-apply,
        // which loses at most the last-applied bookkeeping. Recovering
        // is strictly better than taking the daemon down over a log
        // filter.
        let mut applied = self.applied.lock().unwrap_or_else(|e| e.into_inner());
        if *applied == level {
            return;
        }
        match self.handle.reload(EnvFilter::new(spec_for(level))) {
            Ok(()) => {
                *applied = level;
                tracing::info!(log_level = level.as_str(), "log level applied from config");
            }
            Err(e) => {
                tracing::error!(error = %e, "could not update the log filter; level unchanged");
            }
        }
    }
}

static CONTROL: OnceLock<LogControl> = OnceLock::new();

/// The level the filter starts at, before any config is read.
const STARTUP_LEVEL: LogLevel = LogLevel::Info;

/// Install the process subscriber. Call once, first thing in `main`.
pub fn init() {
    let resolved = resolve(std::env::var(EnvFilter::DEFAULT_ENV).ok(), STARTUP_LEVEL);
    let source = resolved.source;
    let (filter_layer, handle) = reload::Layer::new(resolved.filter);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .compact(),
        )
        .init();

    let _ = CONTROL.set(LogControl::new(handle, source, STARTUP_LEVEL));

    if let Some(w) = resolved.warning {
        tracing::warn!("{w}");
    }
}

/// Point the filter at a config-supplied level. Idempotent, cheap when
/// the level is unchanged, and a no-op when `RUST_LOG` owns the filter
/// or [`init`] was never called.
pub fn apply_config_level(level: LogLevel) {
    if let Some(control) = CONTROL.get() {
        control.apply(level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::filter::LevelFilter;

    /// Build the same layer stack [`init`] does, but scoped to this
    /// thread instead of the process, so the precedence rules can be
    /// exercised end-to-end (real `EnvFilter`, real reload handle)
    /// without a global subscriber that only one test could own.
    ///
    /// The guard keeps the subscriber — and with it the layer the
    /// handle points at — alive for the caller's lifetime.
    fn control_with(env: Option<&str>) -> (LogControl, DefaultGuard) {
        let resolved = resolve(env.map(str::to_owned), STARTUP_LEVEL);
        let source = resolved.source;
        let (filter_layer, handle) = reload::Layer::new(resolved.filter);
        let guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(filter_layer));
        (LogControl::new(handle, source, STARTUP_LEVEL), guard)
    }

    /// The most permissive level the live filter will admit.
    fn live_max(control: &LogControl) -> Option<LevelFilter> {
        control.handle.with_current(|f| f.max_level_hint()).unwrap()
    }

    /// The live filter's directives, as written back out.
    fn live_spec(control: &LogControl) -> String {
        control.handle.with_current(|f| f.to_string()).unwrap()
    }

    #[test]
    fn config_level_reaches_the_filter() {
        let (control, _guard) = control_with(None);
        assert_eq!(live_max(&control), Some(LevelFilter::INFO));

        control.apply(LogLevel::Debug);
        assert_eq!(live_max(&control), Some(LevelFilter::DEBUG));

        // …and back down again: hot-reload is not one-way.
        control.apply(LogLevel::Error);
        assert_eq!(live_max(&control), Some(LevelFilter::ERROR));
    }

    #[test]
    fn rust_log_beats_the_config_level() {
        let (control, _guard) = control_with(Some("warn"));
        assert_eq!(live_max(&control), Some(LevelFilter::WARN));

        control.apply(LogLevel::Debug);
        assert_eq!(
            live_max(&control),
            Some(LevelFilter::WARN),
            "RUST_LOG must pin the filter for the life of the process"
        );
    }

    /// `EnvFilter` accepts a lot — a bare `nonsense` is a target at
    /// trace, not an error — so this uses a spec it genuinely rejects:
    /// a directive with a level that is not a level.
    #[test]
    fn unparseable_rust_log_leaves_the_config_in_charge() {
        let (control, _guard) = control_with(Some("debug,fast_path=bananas"));
        assert_eq!(control.source, FilterSource::Config);
        assert_eq!(live_max(&control), Some(LevelFilter::INFO));

        control.apply(LogLevel::Trace);
        assert_eq!(live_max(&control), Some(LevelFilter::TRACE));
    }

    #[test]
    fn bgpkit_noise_stays_suppressed_at_every_level() {
        for level in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            let spec = spec_for(level);
            assert!(spec.starts_with(level.as_str()), "{spec}");
            assert!(spec.contains(BGPKIT_NLRI_NOISE), "{spec}");
        }

        // Not just in the string we hand over — in the filter that
        // comes back out after a reload.
        let (control, _guard) = control_with(None);
        control.apply(LogLevel::Trace);
        assert!(
            live_spec(&control).contains("bgpkit_parser::parser::bgp::messages=error"),
            "{}",
            live_spec(&control)
        );
    }

    #[test]
    fn re_applying_the_same_level_is_a_no_op() {
        let (control, _guard) = control_with(None);
        control.apply(LogLevel::Info);
        assert_eq!(live_max(&control), Some(LevelFilter::INFO));
        assert_eq!(*control.applied.lock().unwrap(), LogLevel::Info);
    }
}
