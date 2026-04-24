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
    /// Pause between per-iface attaches during `packetframe run` to let
    /// each link settle before the next attach touches the driver. See
    /// SPEC.md §11.8 — on some drivers (rvu-nicpf observed) XDP attach
    /// briefly bounces the link, and attaching two bridge slaves of the
    /// same bridge inside one STP reconvergence window can trigger an
    /// L2 loop. Default 2s. `0s` disables.
    #[serde(with = "duration_seconds_serde")]
    pub attach_settle_time: Duration,
}

pub const DEFAULT_ATTACH_SETTLE_TIME: Duration = Duration::from_secs(2);

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            metrics_textfile: None,
            log_level: LogLevel::Info,
            bpffs_root: PathBuf::from(DEFAULT_BPFFS_ROOT),
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            attach_settle_time: DEFAULT_ATTACH_SETTLE_TIME,
        }
    }
}

mod duration_seconds_serde {
    use serde::Serializer;
    use std::time::Duration;

    pub fn serialize<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Keep the same `Ns` convention as `circuit-breaker window`.
        s.serialize_str(&format!("{}s", d.as_secs()))
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
    /// Operator override for a driver-specific workaround. Currently
    /// the only defined knob is `rvu-nicpf-head-shift` (SPEC
    /// §11.1(c)) — see [`DriverWorkaround`] for the axes.
    DriverWorkaround(DriverWorkaround),
    // --- Custom FIB (Option F, Phase 1) ---
    /// Selects the forwarding lookup path. `kernel-fib` (default)
    /// uses the existing `bpf_fib_lookup()`; `custom-fib` consults
    /// the module's own LPM-trie FIB + NEXTHOPS array; `compare`
    /// runs both and bumps CompareAgree/CompareDisagree (pre-cutover
    /// validation, temporary).
    ForwardingMode(ForwardingMode),
    /// RouteSource configuration — where the custom FIB gets its
    /// routes. Two kinds: `bmp <addr>:<port>` and `bgp <addr>:<port>
    /// local-as <asn> peer-as <asn>`. Spawned by the RouteController
    /// when this is set and `forwarding-mode` is `custom-fib` or
    /// `compare`. See [`RouteSourceSpec`] for the per-kind shape.
    RouteSource(RouteSourceSpec),
    /// Max entries for the custom-FIB LPM tries and side arrays.
    /// Accepted but **not yet runtime-applied** — aya / kernel
    /// allocate maps at compile-time sizes set in
    /// `crates/modules/fast-path/bpf/src/maps.rs`. The directive is
    /// preserved for operator config forward-compatibility; actual
    /// runtime sizing requires a recompile of the BPF ELF with
    /// matching constants.
    FibSize(FibSizeDirective),
    /// Default ECMP hash tuple width (3, 4, or 5). Written into
    /// `FIB_CONFIG.default_hash_mode` at load time.
    EcmpDefaultHashMode(EcmpHashMode),
}

/// Forwarding-path selector. `KernelFib` keeps today's behavior —
/// bpf_fib_lookup() and the legacy success path. `CustomFib` routes
/// through the Option-F LPM trie + nexthop cache. `Compare` runs
/// both and bumps disagreement counters; the kernel result is
/// authoritative.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardingMode {
    #[default]
    KernelFib,
    CustomFib,
    Compare,
}

impl FromStr for ForwardingMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kernel-fib" => Ok(Self::KernelFib),
            "custom-fib" => Ok(Self::CustomFib),
            "compare" => Ok(Self::Compare),
            other => Err(format!(
                "expected `kernel-fib`, `custom-fib`, or `compare`, got `{other}`"
            )),
        }
    }
}

/// RouteSource configuration. Two impls today: BMP and iBGP. BGP
/// is the recommended forwarding feed because bird's BMP
/// implementation lacks RFC 9069 Loc-RIB — see
/// `route_source_bgp.rs` module docs and
/// `docs/runbooks/custom-fib.md` for the rationale.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum RouteSourceSpec {
    /// BMP station listen address. Bird dials out to this
    /// address:port; packetframe accepts the TCP connection and
    /// consumes the BMP stream. RFC 7854 roles: bird is the router
    /// (client), packetframe is the station (server).
    ///
    /// `require_loc_rib`: when true, only RouteMonitoring frames
    /// with peer_type = 3 (RFC 9069 Loc-RIB Instance Peer) are
    /// accepted; pre/post-policy frames cause the session to be
    /// torn down with an error. **This is required for safe use
    /// against pre/post-policy emitters** like bird 2.x — without
    /// it, multiple peers' Adj-RIB-In streams would race-overwrite
    /// per-prefix nexthops in the FIB and produce silent
    /// wrong-forwarding. See module docs in
    /// `route_source_bmp.rs`.
    Bmp {
        addr: String,
        port: u16,
        require_loc_rib: bool,
    },
    /// iBGP listener — packetframe accepts an iBGP session from
    /// bird and ingests UPDATEs as bird's selected best paths.
    /// `local_as`/`peer_as` are typically equal (iBGP within one AS);
    /// `router_id` defaults to `addr` when not specified.
    Bgp {
        addr: String,
        port: u16,
        local_as: u32,
        peer_as: u32,
        router_id: Option<std::net::Ipv4Addr>,
    },
}

/// One `fib-*-max-entries` directive. Parsed but not runtime-applied
/// — see the doc on [`ModuleDirective::FibSize`].
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum FibSizeDirective {
    FibV4MaxEntries(u32),
    FibV6MaxEntries(u32),
    NexthopsMaxEntries(u32),
    EcmpGroupsMaxEntries(u32),
}

/// ECMP hash tuple width. `Three` = src/dst/proto, `Four` = + one
/// port, `Five` = + both ports. The numeric wire value is the tuple
/// width and is what `EcmpGroup.hash_mode` stores.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EcmpHashMode {
    Three,
    Four,
    Five,
}

impl EcmpHashMode {
    pub fn as_wire(self) -> u8 {
        match self {
            Self::Three => 3,
            Self::Four => 4,
            Self::Five => 5,
        }
    }
}

impl FromStr for EcmpHashMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "3" => Ok(Self::Three),
            "4" => Ok(Self::Four),
            "5" => Ok(Self::Five),
            other => Err(format!("expected `3`, `4`, or `5`, got `{other}`")),
        }
    }
}

/// One line of `driver-workaround <name> <value>` config.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum DriverWorkaround {
    /// Controls whether the fast-path BPF program applies the
    /// pre-Linux-v6.8 `bpf_xdp_adjust_head(+128)` /
    /// `bpf_xdp_adjust_tail(+128)` shim (SPEC §11.1(c)). `Auto`
    /// detects the `rvu-nicpf` driver via `/sys/class/net/*/device/driver`
    /// and applies only on native-mode attaches; `On` forces it on
    /// (useful for non-rvu drivers that exhibit the same pattern);
    /// `Off` disables it entirely (correct once the kernel ships the
    /// upstream commit 04f647c8e456 fix).
    RvuNicpfHeadShift(ToggleAutoOnOff),
}

/// Tri-state on/off/auto toggle used by driver workarounds.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToggleAutoOnOff {
    #[default]
    Auto,
    On,
    Off,
}

impl FromStr for ToggleAutoOnOff {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(Self::Auto),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            other => Err(format!("expected `auto`, `on`, or `off`, got `{other}`")),
        }
    }
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
        "attach-settle-time" => {
            let tok = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "attach-settle-time requires a duration (e.g. `2s`, `500ms`)",
                )
            })?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "attach-settle-time takes exactly one argument",
                ));
            }
            g.attach_settle_time = parse_duration(line, tok, "attach-settle-time")?;
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
        "driver-workaround" => parse_driver_workaround(line, rest),
        "forwarding-mode" => parse_single_arg(line, rest, "forwarding-mode", |t| {
            let mode: ForwardingMode = t.parse().map_err(|e: String| e)?;
            Ok(ModuleDirective::ForwardingMode(mode))
        }),
        "route-source" => parse_route_source(line, rest),
        "fib-v4-max-entries" => parse_u32_directive(line, rest, "fib-v4-max-entries", |n| {
            ModuleDirective::FibSize(FibSizeDirective::FibV4MaxEntries(n))
        }),
        "fib-v6-max-entries" => parse_u32_directive(line, rest, "fib-v6-max-entries", |n| {
            ModuleDirective::FibSize(FibSizeDirective::FibV6MaxEntries(n))
        }),
        "nexthops-max-entries" => parse_u32_directive(line, rest, "nexthops-max-entries", |n| {
            ModuleDirective::FibSize(FibSizeDirective::NexthopsMaxEntries(n))
        }),
        "ecmp-groups-max-entries" => {
            parse_u32_directive(line, rest, "ecmp-groups-max-entries", |n| {
                ModuleDirective::FibSize(FibSizeDirective::EcmpGroupsMaxEntries(n))
            })
        }
        "ecmp-default-hash-mode" => parse_single_arg(line, rest, "ecmp-default-hash-mode", |t| {
            let mode: EcmpHashMode = t.parse().map_err(|e: String| e)?;
            Ok(ModuleDirective::EcmpDefaultHashMode(mode))
        }),
        other => Err(ConfigError::parse(
            line,
            format!("unknown directive `{other}` in module section"),
        )),
    }
}

/// Helper: one argument → one `ModuleDirective`. Centralizes the
/// "exactly one token, errors if missing or if trailing tokens" check.
fn parse_single_arg<'a, F>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
    directive: &'static str,
    f: F,
) -> Result<ModuleDirective, ConfigError>
where
    F: FnOnce(&'a str) -> Result<ModuleDirective, String>,
{
    let tok = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, format!("{directive} requires a value")))?;
    if rest.next().is_some() {
        return Err(ConfigError::parse(
            line,
            format!("{directive} takes exactly one argument"),
        ));
    }
    f(tok).map_err(|e| ConfigError::parse(line, format!("{directive}: {e}")))
}

/// Helper: single-u32 argument variants (`fib-*-max-entries`).
fn parse_u32_directive<'a, F>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
    directive: &'static str,
    wrap: F,
) -> Result<ModuleDirective, ConfigError>
where
    F: FnOnce(u32) -> ModuleDirective,
{
    let tok = rest.next().ok_or_else(|| {
        ConfigError::parse(line, format!("{directive} requires a positive integer"))
    })?;
    if rest.next().is_some() {
        return Err(ConfigError::parse(
            line,
            format!("{directive} takes exactly one argument"),
        ));
    }
    let n: u32 = tok
        .parse()
        .map_err(|e| ConfigError::parse(line, format!("{directive}: bad integer `{tok}`: {e}")))?;
    if n == 0 {
        return Err(ConfigError::parse(
            line,
            format!("{directive}: must be >= 1, got 0"),
        ));
    }
    Ok(wrap(n))
}

/// Parse `route-source <kind> <args...>`. Two kinds supported:
/// - `bmp <addr>:<port>`
/// - `bgp <addr>:<port> local-as <asn> peer-as <asn> [router-id <ipv4>]`
///
/// Unknown kinds become parse errors with an explicit message.
fn parse_route_source<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    let kind = rest.next().ok_or_else(|| {
        ConfigError::parse(
            line,
            "route-source requires a kind + args (e.g. `bgp 127.0.0.1:1179 local-as 401401 peer-as 401401`)",
        )
    })?;
    match kind {
        "bmp" => {
            let endpoint = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "route-source bmp requires <addr>:<port>")
            })?;
            let (addr, port) = parse_endpoint(line, endpoint, "bmp")?;
            // Optional trailing `require-loc-rib` flag. Any other
            // tail token is a parse error.
            let mut require_loc_rib = false;
            for tok in rest {
                match tok {
                    "require-loc-rib" => require_loc_rib = true,
                    other => {
                        return Err(ConfigError::parse(
                            line,
                            format!(
                                "route-source bmp: unknown tail flag `{other}` (only `require-loc-rib` is recognized)"
                            ),
                        ));
                    }
                }
            }
            Ok(ModuleDirective::RouteSource(RouteSourceSpec::Bmp {
                addr,
                port,
                require_loc_rib,
            }))
        }
        "bgp" => {
            let endpoint = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "route-source bgp requires <addr>:<port> local-as <asn> peer-as <asn>",
                )
            })?;
            let (addr, port) = parse_endpoint(line, endpoint, "bgp")?;
            let mut local_as: Option<u32> = None;
            let mut peer_as: Option<u32> = None;
            let mut router_id: Option<std::net::Ipv4Addr> = None;
            while let Some(key) = rest.next() {
                let value = rest.next().ok_or_else(|| {
                    ConfigError::parse(
                        line,
                        format!("route-source bgp: `{key}` requires a value"),
                    )
                })?;
                match key {
                    "local-as" => {
                        local_as = Some(value.parse::<u32>().map_err(|e| {
                            ConfigError::parse(
                                line,
                                format!("route-source bgp: bad local-as `{value}`: {e}"),
                            )
                        })?);
                    }
                    "peer-as" => {
                        peer_as = Some(value.parse::<u32>().map_err(|e| {
                            ConfigError::parse(
                                line,
                                format!("route-source bgp: bad peer-as `{value}`: {e}"),
                            )
                        })?);
                    }
                    "router-id" => {
                        router_id = Some(value.parse::<std::net::Ipv4Addr>().map_err(|e| {
                            ConfigError::parse(
                                line,
                                format!("route-source bgp: bad router-id `{value}`: {e}"),
                            )
                        })?);
                    }
                    other => {
                        return Err(ConfigError::parse(
                            line,
                            format!(
                                "route-source bgp: unknown key `{other}` (known: local-as, peer-as, router-id)"
                            ),
                        ));
                    }
                }
            }
            let local_as = local_as.ok_or_else(|| {
                ConfigError::parse(line, "route-source bgp: missing required `local-as <asn>`")
            })?;
            let peer_as = peer_as.ok_or_else(|| {
                ConfigError::parse(line, "route-source bgp: missing required `peer-as <asn>`")
            })?;
            Ok(ModuleDirective::RouteSource(RouteSourceSpec::Bgp {
                addr,
                port,
                local_as,
                peer_as,
                router_id,
            }))
        }
        other => Err(ConfigError::parse(
            line,
            format!(
                "route-source `{other}` unknown (supported: `bmp <addr>:<port>`, `bgp <addr>:<port> local-as <asn> peer-as <asn> [router-id <ipv4>]`)"
            ),
        )),
    }
}

/// Common `<addr>:<port>` parser, used by both `bmp` and `bgp`
/// kinds. `kind_label` is interpolated into error messages.
fn parse_endpoint(
    line: usize,
    endpoint: &str,
    kind_label: &str,
) -> Result<(String, u16), ConfigError> {
    let (addr, port_str) = endpoint.rsplit_once(':').ok_or_else(|| {
        ConfigError::parse(
            line,
            format!("route-source {kind_label}: expected <addr>:<port>, got `{endpoint}`"),
        )
    })?;
    if addr.is_empty() {
        return Err(ConfigError::parse(
            line,
            format!("route-source {kind_label}: addr is empty"),
        ));
    }
    let port: u16 = port_str.parse().map_err(|e| {
        ConfigError::parse(
            line,
            format!("route-source {kind_label}: bad port `{port_str}`: {e}"),
        )
    })?;
    Ok((addr.to_string(), port))
}

fn parse_driver_workaround<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    let name = rest.next().ok_or_else(|| {
        ConfigError::parse(
            line,
            "driver-workaround requires a name + value (e.g. `rvu-nicpf-head-shift auto`)",
        )
    })?;
    let value_tok = rest.next().ok_or_else(|| {
        ConfigError::parse(
            line,
            format!("driver-workaround `{name}` requires a value (`auto`, `on`, or `off`)"),
        )
    })?;
    if rest.next().is_some() {
        return Err(ConfigError::parse(
            line,
            "driver-workaround takes exactly two arguments: <name> <value>",
        ));
    }
    let value: ToggleAutoOnOff = value_tok.parse().map_err(|e: String| {
        ConfigError::parse(line, format!("driver-workaround `{name}`: {e}"))
    })?;
    match name {
        "rvu-nicpf-head-shift" => Ok(ModuleDirective::DriverWorkaround(
            DriverWorkaround::RvuNicpfHeadShift(value),
        )),
        other => Err(ConfigError::parse(
            line,
            format!("unknown driver-workaround `{other}` (known: `rvu-nicpf-head-shift`)"),
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

/// Parse a duration literal. Accepts `Nms` and `Ns` suffixes.
/// `context` is the directive name, used for error messages.
/// Zero is allowed (for disabling settle time).
fn parse_duration(line: usize, tok: &str, context: &str) -> Result<Duration, ConfigError> {
    if let Some(rest) = tok.strip_suffix("ms") {
        let ms: u64 = rest.parse().map_err(|e| {
            ConfigError::parse(line, format!("{context}: bad duration `{tok}`: {e}"))
        })?;
        Ok(Duration::from_millis(ms))
    } else if let Some(rest) = tok.strip_suffix('s') {
        let s: u64 = rest.parse().map_err(|e| {
            ConfigError::parse(line, format!("{context}: bad duration `{tok}`: {e}"))
        })?;
        Ok(Duration::from_secs(s))
    } else {
        Err(ConfigError::parse(
            line,
            format!("{context}: duration must end in `s` or `ms`, got `{tok}`"),
        ))
    }
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
    fn attach_settle_time_seconds() {
        let c = Config::parse("global\n  attach-settle-time 5s\n").expect("parse");
        assert_eq!(c.global.attach_settle_time, Duration::from_secs(5));
    }

    #[test]
    fn attach_settle_time_milliseconds() {
        let c = Config::parse("global\n  attach-settle-time 250ms\n").expect("parse");
        assert_eq!(c.global.attach_settle_time, Duration::from_millis(250));
    }

    #[test]
    fn attach_settle_time_zero_allowed() {
        let c = Config::parse("global\n  attach-settle-time 0s\n").expect("parse");
        assert_eq!(c.global.attach_settle_time, Duration::ZERO);
    }

    #[test]
    fn attach_settle_time_default_is_2s() {
        let c = Config::parse("global\n").expect("parse");
        assert_eq!(c.global.attach_settle_time, Duration::from_secs(2));
    }

    #[test]
    fn attach_settle_time_bad_suffix_errors() {
        let err = Config::parse("global\n  attach-settle-time 5min\n").expect_err("must fail");
        assert!(format!("{err}").contains("duration must end in `s` or `ms`"));
    }

    #[test]
    fn attach_settle_time_bad_number_errors() {
        let err = Config::parse("global\n  attach-settle-time abcs\n").expect_err("must fail");
        assert!(format!("{err}").contains("bad duration"));
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

    // --- Option F config directive tests ---

    fn parse_module_body(body: &str) -> Result<ModuleSection, ConfigError> {
        let s = format!("module fast-path\n{body}");
        let mut c = Config::parse(&s)?;
        Ok(c.modules.remove(0))
    }

    #[test]
    fn forwarding_mode_accepts_all_three_values() {
        for (tok, expected) in [
            ("kernel-fib", ForwardingMode::KernelFib),
            ("custom-fib", ForwardingMode::CustomFib),
            ("compare", ForwardingMode::Compare),
        ] {
            let m = parse_module_body(&format!("  forwarding-mode {tok}\n")).unwrap();
            assert_eq!(
                m.directives.iter().find_map(|d| match d {
                    ModuleDirective::ForwardingMode(m) => Some(*m),
                    _ => None,
                }),
                Some(expected),
                "failed for {tok}"
            );
        }
    }

    #[test]
    fn forwarding_mode_rejects_unknown_value() {
        let e = parse_module_body("  forwarding-mode foo\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("foo"), "msg was {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    fn extract_route_source(s: &str) -> RouteSourceSpec {
        let m = parse_module_body(s).unwrap();
        m.directives
            .iter()
            .find_map(|d| match d {
                ModuleDirective::RouteSource(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn route_source_bmp_parses_endpoint() {
        match extract_route_source("  route-source bmp 127.0.0.1:6543\n") {
            RouteSourceSpec::Bmp {
                addr,
                port,
                require_loc_rib,
            } => {
                assert_eq!(addr, "127.0.0.1");
                assert_eq!(port, 6543);
                assert!(!require_loc_rib, "default should be off");
            }
            other => panic!("expected Bmp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bmp_ipv6_endpoint() {
        // rsplit_once(':') on `[::1]:6543` cleanly splits off the port.
        match extract_route_source("  route-source bmp [::1]:6543\n") {
            RouteSourceSpec::Bmp { addr, port, .. } => {
                assert_eq!(addr, "[::1]");
                assert_eq!(port, 6543);
            }
            other => panic!("expected Bmp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bmp_require_loc_rib_flag() {
        match extract_route_source("  route-source bmp 127.0.0.1:6543 require-loc-rib\n") {
            RouteSourceSpec::Bmp {
                require_loc_rib, ..
            } => assert!(require_loc_rib),
            other => panic!("expected Bmp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bmp_unknown_tail_flag_errors() {
        let e = parse_module_body("  route-source bmp 127.0.0.1:6543 require-pre-policy\n")
            .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(
                    message.contains("require-pre-policy") || message.contains("unknown tail"),
                    "msg was: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bmp_missing_port_errors() {
        let e = parse_module_body("  route-source bmp 127.0.0.1\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn route_source_unknown_kind_errors() {
        let e = parse_module_body("  route-source frr /run/frr/frr.fpm\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("frr") || message.contains("unknown"));
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_parses_full_form() {
        let s = "  route-source bgp 127.0.0.1:1179 local-as 401401 peer-as 401401 router-id 103.17.154.7\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bgp {
                addr,
                port,
                local_as,
                peer_as,
                router_id,
            } => {
                assert_eq!(addr, "127.0.0.1");
                assert_eq!(port, 1179);
                assert_eq!(local_as, 401401);
                assert_eq!(peer_as, 401401);
                assert_eq!(router_id, Some("103.17.154.7".parse().unwrap()));
            }
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_router_id_optional() {
        let s = "  route-source bgp 127.0.0.1:1179 local-as 64512 peer-as 64512\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bgp { router_id, .. } => assert_eq!(router_id, None),
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_missing_local_as_errors() {
        let e =
            parse_module_body("  route-source bgp 127.0.0.1:1179 peer-as 401401\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("local-as"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_unknown_key_errors() {
        let e = parse_module_body(
            "  route-source bgp 127.0.0.1:1179 local-as 1 peer-as 2 hold-time 60\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(
                    message.contains("hold-time") || message.contains("unknown key"),
                    "msg was: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_bad_router_id_errors() {
        let e = parse_module_body(
            "  route-source bgp 127.0.0.1:1179 local-as 1 peer-as 2 router-id not-an-ip\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("router-id"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn fib_max_entries_parse_and_reject_zero() {
        let m = parse_module_body("  fib-v4-max-entries 1048576\n").unwrap();
        assert!(m.directives.iter().any(|d| matches!(
            d,
            ModuleDirective::FibSize(FibSizeDirective::FibV4MaxEntries(1048576))
        )));

        let e = parse_module_body("  fib-v4-max-entries 0\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => assert!(message.contains(">= 1")),
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn ecmp_default_hash_mode_parses_valid_widths() {
        for (tok, expected) in [
            ("3", EcmpHashMode::Three),
            ("4", EcmpHashMode::Four),
            ("5", EcmpHashMode::Five),
        ] {
            let m = parse_module_body(&format!("  ecmp-default-hash-mode {tok}\n")).unwrap();
            assert_eq!(
                m.directives.iter().find_map(|d| match d {
                    ModuleDirective::EcmpDefaultHashMode(m) => Some(*m),
                    _ => None,
                }),
                Some(expected)
            );
        }
    }

    #[test]
    fn ecmp_default_hash_mode_rejects_other_widths() {
        let e = parse_module_body("  ecmp-default-hash-mode 6\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }
}
