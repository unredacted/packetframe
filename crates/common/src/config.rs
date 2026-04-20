//! Config parser for PacketFrame (SPEC.md §6).
//!
//! Grammar is line-based. Leading/trailing whitespace and blank lines are
//! ignored. `#` starts an end-of-line comment. A `global` line or a
//! `module <name>` line begins a new section; directives belong to the current
//! section until the next section header. Unknown directives are fatal.
//!
//! Interface-existence checks for `attach` directives are performed by
//! [`Config::validate_interfaces`] rather than the parser — the parser stays
//! pure so it can run in contexts without `/sys/class/net` (tests, non-root,
//! cross-host audit).

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

pub const DEFAULT_BPFFS_ROOT: &str = "/sys/fs/bpf/packetframe";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/packetframe/state";

#[derive(Debug, Error)]
pub enum ConfigError {
    // PathBuf doesn't implement Display, so we format it manually via
    // a custom Display impl on a Path wrapper. Use {path:?} for the
    // thiserror-generated message, which round-trips through Debug.
    #[error("I/O error reading {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("parse error at line {line}: {message}")]
    Parse { line: usize, message: String },

    #[error("duplicate section `module {name}` (second occurrence at line {line})")]
    DuplicateModule { name: String, line: usize },

    #[error("duplicate global section (second occurrence at line {line})")]
    DuplicateGlobal { line: usize },

    #[error("interface `{iface}` (line {line}) does not exist in /sys/class/net")]
    InterfaceMissing { iface: String, line: usize },
}

impl ConfigError {
    fn parse(line: usize, msg: impl Into<String>) -> Self {
        Self::Parse {
            line,
            message: msg.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Config {
    pub global: GlobalConfig,
    pub modules: Vec<ModuleSection>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GlobalConfig {
    pub metrics_textfile: Option<PathBuf>,
    pub log_level: LogLevel,
    pub bpffs_root: PathBuf,
    pub state_dir: PathBuf,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            metrics_textfile: None,
            log_level: LogLevel::Info,
            bpffs_root: PathBuf::from(DEFAULT_BPFFS_ROOT),
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl FromStr for LogLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "unknown log-level `{other}` (expected trace|debug|info|warn|error)"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ModuleSection {
    pub name: String,
    pub directives: Vec<ModuleDirective>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ModuleDirective {
    Attach {
        iface: String,
        mode: AttachMode,
        line: usize,
    },
    AllowPrefix4(Ipv4Prefix),
    AllowPrefix6(Ipv6Prefix),
    DryRun(bool),
    CircuitBreaker(CircuitBreakerSpec),
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttachMode {
    Native,
    Generic,
    Auto,
}

impl FromStr for AttachMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native" => Ok(Self::Native),
            "generic" => Ok(Self::Generic),
            "auto" => Ok(Self::Auto),
            other => Err(format!(
                "unknown attach mode `{other}` (expected native|generic|auto)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

impl FromStr for Ipv4Prefix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| format!("expected CIDR (e.g. 10.0.0.0/24), got `{s}`"))?;
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("bad IPv4 `{addr}`: {e}"))?;
        let prefix_len: u8 = len
            .parse()
            .map_err(|e| format!("bad prefix length `{len}`: {e}"))?;
        if prefix_len > 32 {
            return Err(format!(
                "IPv4 prefix length must be 0..=32, got {prefix_len}"
            ));
        }
        Ok(Self { addr, prefix_len })
    }
}

impl FromStr for Ipv6Prefix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| format!("expected CIDR (e.g. 2001:db8::/48), got `{s}`"))?;
        let addr: Ipv6Addr = addr
            .parse()
            .map_err(|e| format!("bad IPv6 `{addr}`: {e}"))?;
        let prefix_len: u8 = len
            .parse()
            .map_err(|e| format!("bad prefix length `{len}`: {e}"))?;
        if prefix_len > 128 {
            return Err(format!(
                "IPv6 prefix length must be 0..=128, got {prefix_len}"
            ));
        }
        Ok(Self { addr, prefix_len })
    }
}

/// Circuit-breaker grammar:
///   circuit-breaker drop-ratio <float> of <denominator> window <dur>s threshold <int>
///
/// v0.0.1 accepts only `of matched`. The `of rx` form is recognized as a
/// reserved token and rejected with an explicit message; this avoids a
/// silent-accept forward-compat gap (see SPEC.md §4.9).
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct CircuitBreakerSpec {
    pub drop_ratio: f64,
    pub denominator: CircuitBreakerDenominator,
    #[serde(with = "humantime_serde_compat")]
    pub window: Duration,
    pub threshold: u32,
}

// CircuitBreakerSpec is Eq-by-bit-pattern if you squint at the f64 — but we
// don't rely on it. Implement a tolerant Eq for tests without going through
// f64::total_cmp.
impl Eq for CircuitBreakerSpec {}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CircuitBreakerDenominator {
    Matched,
    // Rx — reserved, parser rejects with a clear error in v0.0.1.
}

/// Minimal humantime-like serializer for Duration, so the report JSON shows
/// "5s" rather than "{secs: 5, nanos: 0}". Keeps the dependency surface small.
mod humantime_serde_compat {
    use serde::Serializer;
    use std::time::Duration;

    pub fn serialize<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&format!("{}s", d.as_secs()))
    }
}

impl Config {
    /// Parse a config from a file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&contents)
    }

    /// Parse a config from a string.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        parse(s)
    }

    /// Verify that every `attach`-listed interface exists under
    /// `/sys/class/net`. Per SPEC.md §6 this is a startup-fatal check;
    /// call it after successful parse.
    pub fn validate_interfaces(&self) -> Result<(), ConfigError> {
        self.validate_interfaces_in(Path::new("/sys/class/net"))
    }

    /// Same, but with a caller-provided sysfs root (for tests).
    pub fn validate_interfaces_in(&self, sysfs_net: &Path) -> Result<(), ConfigError> {
        for m in &self.modules {
            for d in &m.directives {
                if let ModuleDirective::Attach { iface, line, .. } = d {
                    let p = sysfs_net.join(iface);
                    if !p.exists() {
                        return Err(ConfigError::InterfaceMissing {
                            iface: iface.clone(),
                            line: *line,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

enum Cursor {
    None,
    Global,
    Module(usize),
}

fn parse(input: &str) -> Result<Config, ConfigError> {
    let mut global: Option<GlobalConfig> = None;
    let mut modules: Vec<ModuleSection> = Vec::new();
    let mut cursor = Cursor::None;

    // `global` and `module` are reserved keywords: they are always parsed as
    // section headers regardless of indentation. Per SPEC.md §6, leading
    // whitespace is ignored, so we can't use indent to disambiguate. Module
    // directives must therefore never be named "global" or "module" — fine,
    // since the grammar enumerates them and does neither.
    for (idx, raw_line) in input.lines().enumerate() {
        let line = idx + 1;
        let stripped = strip_comment(raw_line).trim();
        if stripped.is_empty() {
            continue;
        }

        let head = first_token(stripped);
        match head {
            "global" => {
                if rest_tokens(stripped).next().is_some() {
                    return Err(ConfigError::parse(
                        line,
                        "`global` section header takes no arguments",
                    ));
                }
                if global.is_some() {
                    return Err(ConfigError::DuplicateGlobal { line });
                }
                global = Some(GlobalConfig::default());
                cursor = Cursor::Global;
            }
            "module" => {
                let mut rest = rest_tokens(stripped);
                let name = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "`module` requires a name, e.g. `module fast-path`")
                })?;
                if rest.next().is_some() {
                    return Err(ConfigError::parse(
                        line,
                        "`module <name>` takes exactly one argument",
                    ));
                }
                if modules.iter().any(|m| m.name == name) {
                    return Err(ConfigError::DuplicateModule {
                        name: name.to_string(),
                        line,
                    });
                }
                modules.push(ModuleSection {
                    name: name.to_string(),
                    directives: Vec::new(),
                });
                cursor = Cursor::Module(modules.len() - 1);
            }
            _ => match cursor {
                Cursor::None => {
                    return Err(ConfigError::parse(
                        line,
                        format!(
                            "directive `{head}` outside any section (expected `global` or `module <name>` header first)"
                        ),
                    ));
                }
                Cursor::Global => {
                    let g = global.as_mut().expect("global cursor implies global set");
                    parse_global_directive(line, stripped, g)?;
                }
                Cursor::Module(i) => {
                    let d = parse_module_directive(line, stripped)?;
                    modules[i].directives.push(d);
                }
            },
        }
    }

    Ok(Config {
        global: global.unwrap_or_default(),
        modules,
    })
}

fn parse_global_directive(line: usize, s: &str, g: &mut GlobalConfig) -> Result<(), ConfigError> {
    let head = first_token(s);
    let mut rest = rest_tokens(s);
    match head {
        "metrics-textfile" => {
            let path = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "metrics-textfile requires a path"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "metrics-textfile takes exactly one argument",
                ));
            }
            g.metrics_textfile = Some(PathBuf::from(path));
        }
        "log-level" => {
            let lvl = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "log-level requires a value"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "log-level takes exactly one argument",
                ));
            }
            g.log_level = lvl
                .parse()
                .map_err(|e: String| ConfigError::parse(line, e))?;
        }
        "bpffs-root" => {
            let path = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "bpffs-root requires a path"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "bpffs-root takes exactly one argument",
                ));
            }
            g.bpffs_root = PathBuf::from(path);
        }
        "state-dir" => {
            let path = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "state-dir requires a path"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "state-dir takes exactly one argument",
                ));
            }
            g.state_dir = PathBuf::from(path);
        }
        other => {
            return Err(ConfigError::parse(
                line,
                format!("unknown global directive `{other}`"),
            ));
        }
    }
    Ok(())
}

fn parse_module_directive(line: usize, s: &str) -> Result<ModuleDirective, ConfigError> {
    let head = first_token(s);
    let mut rest = rest_tokens(s);
    match head {
        "attach" => {
            let iface = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "attach requires an interface"))?;
            let mode_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "attach requires a mode: native|generic|auto")
            })?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "attach takes exactly two arguments: <iface> <mode>",
                ));
            }
            let mode: AttachMode = mode_tok
                .parse()
                .map_err(|e: String| ConfigError::parse(line, e))?;
            Ok(ModuleDirective::Attach {
                iface: iface.to_string(),
                mode,
                line,
            })
        }
        "allow-prefix" => {
            let cidr = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "allow-prefix requires a CIDR"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(line, "allow-prefix takes one argument"));
            }
            let p: Ipv4Prefix = cidr
                .parse()
                .map_err(|e: String| ConfigError::parse(line, e))?;
            Ok(ModuleDirective::AllowPrefix4(p))
        }
        "allow-prefix6" => {
            let cidr = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "allow-prefix6 requires a CIDR"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(line, "allow-prefix6 takes one argument"));
            }
            let p: Ipv6Prefix = cidr
                .parse()
                .map_err(|e: String| ConfigError::parse(line, e))?;
            Ok(ModuleDirective::AllowPrefix6(p))
        }
        "dry-run" => {
            let v = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "dry-run requires on|off"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(line, "dry-run takes one argument"));
            }
            let on = match v {
                "on" => true,
                "off" => false,
                other => {
                    return Err(ConfigError::parse(
                        line,
                        format!("dry-run expects on|off, got `{other}`"),
                    ))
                }
            };
            Ok(ModuleDirective::DryRun(on))
        }
        "circuit-breaker" => parse_circuit_breaker(line, rest),
        other => Err(ConfigError::parse(
            line,
            format!("unknown directive `{other}` in module section"),
        )),
    }
}

fn parse_circuit_breaker<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    // Expected: drop-ratio <f> of <denom> window <int>s threshold <int>
    expect_token(&mut rest, line, "drop-ratio")?;
    let ratio_tok = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, "circuit-breaker: missing ratio"))?;
    let drop_ratio: f64 = ratio_tok.parse().map_err(|e| {
        ConfigError::parse(
            line,
            format!("circuit-breaker: bad ratio `{ratio_tok}`: {e}"),
        )
    })?;
    if !(0.0..=1.0).contains(&drop_ratio) || !drop_ratio.is_finite() {
        return Err(ConfigError::parse(
            line,
            format!("circuit-breaker: ratio must be in [0.0, 1.0], got {drop_ratio}"),
        ));
    }

    expect_token(&mut rest, line, "of")?;
    let denom_tok = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, "circuit-breaker: missing denominator"))?;
    let denominator = match denom_tok {
        "matched" => CircuitBreakerDenominator::Matched,
        "rx" => {
            return Err(ConfigError::parse(
                line,
                "circuit-breaker: `of rx` is reserved for future modules and not accepted in v0.0.1 (use `of matched`, see SPEC.md §4.9)",
            ));
        }
        other => {
            return Err(ConfigError::parse(
                line,
                format!("circuit-breaker: unknown denominator `{other}` (expected `matched`)"),
            ))
        }
    };

    expect_token(&mut rest, line, "window")?;
    let win_tok = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, "circuit-breaker: missing window duration"))?;
    let window = parse_window(line, win_tok)?;

    expect_token(&mut rest, line, "threshold")?;
    let thr_tok = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, "circuit-breaker: missing threshold"))?;
    let threshold: u32 = thr_tok.parse().map_err(|e| {
        ConfigError::parse(
            line,
            format!("circuit-breaker: bad threshold `{thr_tok}`: {e}"),
        )
    })?;

    if rest.next().is_some() {
        return Err(ConfigError::parse(
            line,
            "circuit-breaker: trailing tokens after threshold",
        ));
    }

    Ok(ModuleDirective::CircuitBreaker(CircuitBreakerSpec {
        drop_ratio,
        denominator,
        window,
        threshold,
    }))
}

fn expect_token<'a>(
    it: &mut impl Iterator<Item = &'a str>,
    line: usize,
    expected: &'static str,
) -> Result<(), ConfigError> {
    match it.next() {
        Some(t) if t == expected => Ok(()),
        Some(t) => Err(ConfigError::parse(
            line,
            format!("expected `{expected}`, got `{t}`"),
        )),
        None => Err(ConfigError::parse(
            line,
            format!("expected `{expected}`, got end of line"),
        )),
    }
}

fn parse_window(line: usize, tok: &str) -> Result<Duration, ConfigError> {
    let rest = tok.strip_suffix('s').ok_or_else(|| {
        ConfigError::parse(
            line,
            format!("circuit-breaker: window must end in `s`, got `{tok}`"),
        )
    })?;
    let secs: u64 = rest.parse().map_err(|e| {
        ConfigError::parse(line, format!("circuit-breaker: bad window `{tok}`: {e}"))
    })?;
    if secs == 0 {
        return Err(ConfigError::parse(
            line,
            "circuit-breaker: window must be >= 1s",
        ));
    }
    Ok(Duration::from_secs(secs))
}

fn strip_comment(s: &str) -> &str {
    match s.find('#') {
        Some(i) => &s[..i],
        None => s,
    }
}

fn first_token(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

fn rest_tokens(s: &str) -> impl Iterator<Item = &str> {
    s.split_whitespace().skip(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile_shim::TempDir;

    mod tempfile_shim {
        // Minimal tempdir helper so tests don't require a tempfile crate
        // dependency in v0.0.1. Uses the process PID + a counter for
        // uniqueness. Cleanup is best-effort on Drop.
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir {
            pub path: PathBuf,
        }

        impl TempDir {
            pub fn new(prefix: &str) -> Self {
                let n = COUNTER.fetch_add(1, Ordering::SeqCst);
                let path = std::env::temp_dir().join(format!(
                    "packetframe-test-{}-{}-{}",
                    prefix,
                    std::process::id(),
                    n
                ));
                std::fs::create_dir_all(&path).expect("create tempdir");
                TempDir { path }
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    const REF_EFG_CONFIG: &str = r#"
global
  metrics-textfile /var/lib/node_exporter/textfile/packetframe.prom
  log-level info
  bpffs-root /sys/fs/bpf/packetframe
  state-dir /var/lib/packetframe/state

module fast-path
  attach eth0 native
  attach eth2 native
  attach eth3 native
  attach eth4 native
  attach eth5 native
  allow-prefix  23.191.200.0/24
  allow-prefix6 2001:db8::/48
  dry-run on
  circuit-breaker drop-ratio 0.01 of matched window 5s threshold 5
"#;

    #[test]
    fn parses_reference_efg_config() {
        let c = Config::parse(REF_EFG_CONFIG).expect("parse");
        assert_eq!(
            c.global.metrics_textfile,
            Some(PathBuf::from(
                "/var/lib/node_exporter/textfile/packetframe.prom"
            ))
        );
        assert_eq!(c.global.log_level, LogLevel::Info);
        assert_eq!(
            c.global.bpffs_root,
            PathBuf::from("/sys/fs/bpf/packetframe")
        );
        assert_eq!(c.modules.len(), 1);
        assert_eq!(c.modules[0].name, "fast-path");

        let attaches: Vec<&str> = c.modules[0]
            .directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::Attach { iface, .. } => Some(iface.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(attaches, vec!["eth0", "eth2", "eth3", "eth4", "eth5"]);

        let dry = c.modules[0]
            .directives
            .iter()
            .find_map(|d| {
                if let ModuleDirective::DryRun(v) = d {
                    Some(*v)
                } else {
                    None
                }
            })
            .unwrap();
        assert!(dry);

        let cb = c.modules[0]
            .directives
            .iter()
            .find_map(|d| {
                if let ModuleDirective::CircuitBreaker(s) = d {
                    Some(*s)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(cb.denominator, CircuitBreakerDenominator::Matched);
        assert_eq!(cb.window, Duration::from_secs(5));
        assert_eq!(cb.threshold, 5);
        assert!((cb.drop_ratio - 0.01).abs() < 1e-9);
    }

    #[test]
    fn minimal_global_only() {
        let c = Config::parse("global\n").expect("parse");
        assert_eq!(c.global, GlobalConfig::default());
        assert!(c.modules.is_empty());
    }

    #[test]
    fn empty_input_uses_defaults() {
        let c = Config::parse("").expect("parse");
        assert_eq!(c.global, GlobalConfig::default());
        assert!(c.modules.is_empty());
    }

    #[test]
    fn comments_and_blank_lines() {
        let s = r#"
# this is a comment
global
  # indented comment
  log-level debug   # trailing comment

module fast-path
  dry-run off
"#;
        let c = Config::parse(s).expect("parse");
        assert_eq!(c.global.log_level, LogLevel::Debug);
        assert_eq!(c.modules.len(), 1);
    }

    #[test]
    fn unknown_directive_is_fatal() {
        let s = "global\n  frobnicate yes\n";
        let e = Config::parse(s).unwrap_err();
        match e {
            ConfigError::Parse { line, message } => {
                assert_eq!(line, 2);
                assert!(message.contains("frobnicate"), "message was {message}");
            }
            _ => panic!("expected Parse, got {e:?}"),
        }
    }

    #[test]
    fn unknown_module_directive_is_fatal() {
        let s = "module fast-path\n  teleport on\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn directive_before_section_is_fatal() {
        let s = "dry-run on\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { line: 1, .. }));
    }

    #[test]
    fn duplicate_global_rejected() {
        let s = "global\nglobal\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::DuplicateGlobal { line: 2 }));
    }

    #[test]
    fn duplicate_module_rejected() {
        let s = "module fast-path\nmodule fast-path\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::DuplicateModule { line: 2, .. }));
    }

    #[test]
    fn attach_without_mode_errors() {
        let s = "module fast-path\n  attach eth0\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { line: 2, .. }));
    }

    #[test]
    fn attach_bad_mode_errors() {
        let s = "module fast-path\n  attach eth0 weird\n";
        let e = Config::parse(s).unwrap_err();
        match e {
            ConfigError::Parse { line, message } => {
                assert_eq!(line, 2);
                assert!(message.contains("weird"), "msg was {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn bad_ipv4_prefix_errors() {
        let s = "module fast-path\n  allow-prefix 256.0.0.0/8\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { line: 2, .. }));
    }

    #[test]
    fn bad_ipv4_prefix_len_errors() {
        let s = "module fast-path\n  allow-prefix 10.0.0.0/40\n";
        let e = Config::parse(s).unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("prefix length"), "msg was {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn circuit_breaker_rx_rejected_with_helpful_message() {
        let s = "module fast-path\n  circuit-breaker drop-ratio 0.01 of rx window 5s threshold 5\n";
        let e = Config::parse(s).unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("rx"), "msg was {message}");
                assert!(message.contains("reserved") || message.contains("matched"));
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn circuit_breaker_bad_ratio_errors() {
        let s =
            "module fast-path\n  circuit-breaker drop-ratio 1.5 of matched window 5s threshold 5\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn circuit_breaker_bad_window_errors() {
        let s = "module fast-path\n  circuit-breaker drop-ratio 0.01 of matched window 5m threshold 5\n";
        let e = Config::parse(s).unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("window"), "msg was {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_bad_value_errors() {
        let s = "module fast-path\n  dry-run maybe\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { line: 2, .. }));
    }

    #[test]
    fn module_without_name_errors() {
        let s = "module\n";
        let e = Config::parse(s).unwrap_err();
        assert!(matches!(e, ConfigError::Parse { line: 1, .. }));
    }

    #[test]
    fn validate_interfaces_happy() {
        let td = TempDir::new("validate_ok");
        // Simulate /sys/class/net by creating the three iface directories.
        for iface in ["eth0", "eth1"] {
            fs::create_dir_all(td.path.join(iface)).unwrap();
        }
        let c = Config::parse(
            r#"
module fast-path
  attach eth0 native
  attach eth1 native
"#,
        )
        .unwrap();
        c.validate_interfaces_in(&td.path).expect("interfaces ok");
    }

    #[test]
    fn validate_interfaces_missing() {
        let td = TempDir::new("validate_missing");
        fs::create_dir_all(td.path.join("eth0")).unwrap();
        let c = Config::parse(
            r#"
module fast-path
  attach eth0 native
  attach eth99 native
"#,
        )
        .unwrap();
        let e = c.validate_interfaces_in(&td.path).unwrap_err();
        match e {
            ConfigError::InterfaceMissing { iface, .. } => assert_eq!(iface, "eth99"),
            other => panic!("expected InterfaceMissing, got {other:?}"),
        }
    }

    #[test]
    fn parses_ipv4_prefix() {
        let p: Ipv4Prefix = "10.0.0.0/8".parse().unwrap();
        assert_eq!(p.addr.octets(), [10, 0, 0, 0]);
        assert_eq!(p.prefix_len, 8);
    }

    #[test]
    fn parses_ipv6_prefix() {
        let p: Ipv6Prefix = "2001:db8::/48".parse().unwrap();
        assert_eq!(p.prefix_len, 48);
    }
}
