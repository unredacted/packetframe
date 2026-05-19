//! Config parser for PacketFrame (SPEC.md §6).
//!
//! Grammar is line-based. Leading/trailing whitespace and blank lines are
//! ignored. `#` starts an end-of-line comment. A `global` line or a
//! `module <name>` line begins a new section; directives belong to the current
//! section until the next section header. Unknown directives are fatal.
//!
//! Interface-existence checks for `attach` directives are performed by
//! [`Config::validate_interfaces`] rather than the parser, the parser stays
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
    /// SPEC.md §11.8, on some drivers (rvu-nicpf observed) XDP attach
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
    /// Connected/local prefix the operator wants packetframe to
    /// fast-path inbound traffic for. Bird's iBGP feed gives us the
    /// /24 with an unresolvable next-hop (a self-IP for direct-origin
    /// routes), so without per-host /32 entries the LPM lookup hits
    /// the /24 with `state=Incomplete` and bumps `custom_fib_no_neigh`
    /// XDP_PASS to kernel for every packet. With a `local-prefix`
    /// directive, [`NetlinkNeighborResolver`] walks the kernel's
    /// neighbour table for IPs within `cidr` reachable via `iface`
    /// and synthesizes per-/32 `RouteEvent::Add { peer_id: LocalArp,
    /// prefix: /32, nexthops: [host_ip] }` events into FibProgrammer.
    /// The host's own MAC (already in the kernel ARP cache) is what
    /// `state=Resolved` writes into `NEXTHOPS[id].dst_mac`, and the
    /// /32 wins in the LPM walk over the /24 from the BGP feed
    /// inbound packets to that customer fast-path via `bpf_redirect_map`.
    /// New in v0.2.1; complements the BgpListener fallback fix.
    LocalPrefix {
        cidr: Ipv4Prefix,
        iface: String,
        /// v0.2.1 issue #32: when true (operator added `arp-scavenge`
        /// after the iface), the resolver issues an ARP probe for every
        /// IP in the CIDR at startup so quiet hosts (e.g. Ceph
        /// nodes that never speak L3 with the gateway) get registered
        /// and fast-pathed. Capped to /22 to avoid `gc_thresh3` overflow
        /// + visible ARP storms on operator networks. Off by default.
        arp_scavenge: bool,
        line: usize,
    },
    /// Synthetic IPv4 default route for the custom FIB (v0.2.1). With
    /// `fallback-default via <iface> nexthop <ipv4>`, the resolver
    /// injects a `RouteEvent::Add { prefix: 0.0.0.0/0, nexthops: [nh] }`
    /// at startup. Every more-specific bird-fed route still wins in
    /// LPM; the /0 catches destinations bird's iBGP feed doesn't have.
    ///
    /// Bird's `default4` is `unreachable` by design (pathvector's
    /// `accept-default: false` keeps stray defaults out of the RIB),
    /// so packetframe never gets a usable 0.0.0.0/0 from the feed.
    /// Without one in the FIB, traffic to destinations bird doesn't
    /// know (RFC 1918, CGNAT, test-net, anything outside DFZ) misses
    /// LPM, falls to slow path, and clogs conntrack with flows that
    /// just get dropped upstream anyway. With this fallback, those
    /// packets XDP-redirect to upstream, same upstream behavior,
    /// but conntrack stays out of it.
    FallbackDefault {
        iface: String,
        nexthop: Ipv4Addr,
        line: usize,
    },
    /// XDP-time prefix block (v0.2.1). When dst (or src for symmetry)
    /// falls in `block-prefix <cidr>` AND the packet is otherwise
    /// allowlist-matched, the program returns `XDP_DROP` rather than
    /// XDP_PASS-to-kernel. Used to drop traffic toward bogons /
    /// RFC 1918 / CGNAT, destinations that would just get RST'd
    /// upstream anyway, but currently waste skb allocation +
    /// netfilter walk + conntrack capacity. Operator opt-in: empty
    /// list = no behavior change.
    BlockPrefix {
        cidr: Ipv4Prefix,
        line: usize,
    },
    /// MSS clamping for matched TCP SYN/SYN-ACK packets (v0.2.4+).
    /// Closes the SPEC §11.4 gap where iptables `TCPMSS` rules don't
    /// fire on fast-pathed flows because XDP redirect bypasses
    /// netfilter. Four grammars:
    ///
    /// - `mss-clamp <mtu>`, global default for all matched TCP SYNs
    /// - `mss-clamp via <iface> <mtu>`, per-egress-iface
    /// - `mss-clamp <cidr> <mtu>`, per-src-or-dst-prefix (any egress)
    /// - `mss-clamp <cidr> via <iface> <mtu>`, most specific
    ///
    /// Lookup precedence at XDP runtime, most specific wins:
    /// `(prefix + iface)` then `prefix` then `iface` then `global`.
    /// Prefix matches on src OR dst (mirrors `allow-prefix`).
    /// Lower-if-higher policy, only rewrites when the SYN's existing
    /// MSS is greater than the configured clamp (matches iptables
    /// `TCPMSS --set-mss` semantics).
    MssClamp {
        prefix: Option<MssClampPrefix>,
        iface: Option<String>,
        mss: u16,
        line: usize,
    },
    DryRun(bool),
    CircuitBreaker(CircuitBreakerSpec),
    /// Operator override for a driver-specific workaround. Currently
    /// the only defined knob is `rvu-nicpf-head-shift` (SPEC
    /// §11.1(c)), see [`DriverWorkaround`] for the axes.
    DriverWorkaround(DriverWorkaround),
    // --- Custom FIB (Option F, Phase 1) ---
    /// Selects the forwarding lookup path. `kernel-fib` (default)
    /// uses the existing `bpf_fib_lookup()`; `custom-fib` consults
    /// the module's own LPM-trie FIB + NEXTHOPS array; `compare`
    /// runs both and bumps CompareAgree/CompareDisagree (pre-cutover
    /// validation, temporary).
    ForwardingMode(ForwardingMode),
    /// RouteSource configuration, where the custom FIB gets its
    /// routes. Two kinds: `bmp <addr>:<port>` and `bgp <addr>:<port>
    /// local-as <asn> peer-as <asn>`. Spawned by the RouteController
    /// when this is set and `forwarding-mode` is `custom-fib` or
    /// `compare`. See [`RouteSourceSpec`] for the per-kind shape.
    RouteSource(RouteSourceSpec),
    /// Max entries for the custom-FIB LPM tries and side arrays.
    /// Accepted but **not yet runtime-applied**, aya / kernel
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

/// One side of the [`ModuleDirective::MssClamp`] discriminator
/// either an IPv4 or IPv6 prefix. Userspace dispatches on this when
/// populating the `MSS_CLAMP_V4` / `MSS_CLAMP_V6` LPM tries.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase", tag = "family", content = "cidr")]
pub enum MssClampPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

/// Forwarding-path selector. `KernelFib` keeps today's behavior
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
/// implementation lacks RFC 9069 Loc-RIB, see
/// `route_source_bgp.rs` module docs and
/// `docs/runbooks/custom-fib.md` for the rationale.
///
/// **Authorization.** The listeners are unauthenticated at the
/// protocol level (no TCP-MD5 wiring). The default posture is
/// loopback-only: a non-loopback listen address is rejected at
/// parse time. Operators who genuinely need a routable bind (e.g.,
/// a netns-segmented deploy where the listener is reachable only
/// inside a private network) must opt in with `allow-remote` and
/// declare an `IpNet` ACL via one or more `peer-from <cidr>` sub-
/// keywords. The BGP variant additionally accepts `peer-ip <ip>`
/// to pin the configured `peer-as` to a specific source address.
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
    /// against pre/post-policy emitters** like bird 2.x, without
    /// it, multiple peers' Adj-RIB-In streams would race-overwrite
    /// per-prefix nexthops in the FIB and produce silent
    /// wrong-forwarding. See module docs in
    /// `route_source_bmp.rs`.
    Bmp {
        addr: String,
        port: u16,
        require_loc_rib: bool,
        /// Operator opt-in for binding a non-loopback listen
        /// address. False (the safe default) makes a non-loopback
        /// listen a parse-time error; true requires at least one
        /// `peer_from` entry.
        allow_remote: bool,
        /// CIDR ACL applied at `accept()` time when `allow_remote`
        /// is true: peers whose source IP doesn't fall in any
        /// entry are rejected before the BMP framing starts. Empty
        /// is parse-rejected when `allow_remote` is true; ignored
        /// (must be empty) when `allow_remote` is false.
        peer_from: Vec<ipnet::IpNet>,
    },
    /// iBGP listener, packetframe accepts an iBGP session from
    /// bird and ingests UPDATEs as bird's selected best paths.
    /// `local_as`/`peer_as` are typically equal (iBGP within one AS);
    /// `router_id` defaults to `addr` when not specified.
    Bgp {
        addr: String,
        port: u16,
        local_as: u32,
        peer_as: u32,
        router_id: Option<std::net::Ipv4Addr>,
        /// Operator opt-in for binding a non-loopback listen
        /// address. See [`RouteSourceSpec::Bmp::allow_remote`].
        allow_remote: bool,
        /// CIDR ACL on the peer's source IP. See
        /// [`RouteSourceSpec::Bmp::peer_from`].
        peer_from: Vec<ipnet::IpNet>,
        /// Optional pin on the peer's source IP. When set, an
        /// accepted connection whose source IP differs is closed.
        /// Combined with the peer-AS check in
        /// `route_source_bgp::handle_connection`, this is the only
        /// real identity binding available in the absence of
        /// TCP-MD5 / TCP-AO.
        peer_ip: Option<std::net::IpAddr>,
    },
}

/// One `fib-*-max-entries` directive. Parsed but not runtime-applied
/// see the doc on [`ModuleDirective::FibSize`].
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

// CircuitBreakerSpec is Eq-by-bit-pattern if you squint at the f64, but we
// don't rely on it. Implement a tolerant Eq for tests without going through
// f64::total_cmp.
impl Eq for CircuitBreakerSpec {}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CircuitBreakerDenominator {
    Matched,
    // Rx, reserved, parser rejects with a clear error in v0.0.1.
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

/// Cap on the size of a config file `from_file` will read. The
/// audit Slice 5 finding: `fs::read_to_string` was unbounded, so a
/// pathological or hostile config file could drag the process into
/// a multi-GiB heap allocation at startup. Real packetframe configs
/// are well under 50 KiB; 1 MiB is 20× headroom for the operator
/// adding comments and still 4 orders of magnitude smaller than the
/// memory primitive the previous behavior exposed.
pub const MAX_CONFIG_FILE_SIZE: u64 = 1 << 20;

impl Config {
    /// Parse a config from a file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        // Pre-flight size check via metadata so we never `read_to_string`
        // a runaway file. Symlinks are followed deliberately, operators
        // do symlink configs in deploy layouts, but a deeply nested
        // attacker-pointed symlink chain bottoms out at a real file
        // whose size we can still measure here.
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > MAX_CONFIG_FILE_SIZE {
                return Err(ConfigError::Parse {
                    line: 0,
                    message: format!(
                        "config file {} is {} bytes; cap is {} bytes (audit Slice 5: \
                         bounded read prevents memory DoS via a runaway config)",
                        path.display(),
                        meta.len(),
                        MAX_CONFIG_FILE_SIZE
                    ),
                });
            }
        }
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
                let (iface, line) = match d {
                    ModuleDirective::Attach { iface, line, .. } => (iface, line),
                    ModuleDirective::LocalPrefix { iface, line, .. } => (iface, line),
                    ModuleDirective::FallbackDefault { iface, line, .. } => (iface, line),
                    _ => continue,
                };
                let p = sysfs_net.join(iface);
                if !p.exists() {
                    return Err(ConfigError::InterfaceMissing {
                        iface: iface.clone(),
                        line: *line,
                    });
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
    // directives must therefore never be named "global" or "module", fine,
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

/// Max iface name length the Linux kernel accepts (`IFNAMSIZ - 1`,
/// where `IFNAMSIZ = 16` reserves a trailing NUL byte). `if_nametoindex`
/// rejects anything longer at attach time, but parse-time validation
/// catches the typo earlier and gives a better error.
const MAX_IFACE_LEN: usize = 15;

/// Reject iface names that contain shell / path / NUL metacharacters.
/// `if_nametoindex` rejects most of these anyway, but the audit Slice
/// 5 hardening prefers a clear config-time error to a deep-runtime
/// `ENODEV`. The list mirrors the kernel's `dev_valid_name()` and
/// adds the path-traversal `..` case for our own iface-keyed maps.
fn validate_iface_name(line: usize, key: &str, iface: &str) -> Result<(), ConfigError> {
    if iface.is_empty() {
        return Err(ConfigError::parse(
            line,
            format!("{key}: interface name is empty"),
        ));
    }
    if iface.len() > MAX_IFACE_LEN {
        return Err(ConfigError::parse(
            line,
            format!(
                "{key}: interface name `{iface}` is {} bytes; kernel cap is {} (IFNAMSIZ - 1)",
                iface.len(),
                MAX_IFACE_LEN
            ),
        ));
    }
    if iface == "." || iface == ".." {
        return Err(ConfigError::parse(
            line,
            format!("{key}: interface name `{iface}` is reserved"),
        ));
    }
    for ch in iface.chars() {
        match ch {
            '/' | '\\' | '\0' => {
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "{key}: interface name `{iface}` contains a forbidden character (`/`, `\\`, or NUL)"
                    ),
                ));
            }
            c if c.is_whitespace() => {
                return Err(ConfigError::parse(
                    line,
                    format!("{key}: interface name `{iface}` contains whitespace"),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Cross-check a path value the operator supplied for a daemon-
/// trusted destination (metrics-textfile, bpffs-root, state-dir).
/// Rejects: relative paths, embedded NUL bytes, any `..` component.
/// These three fields are consumed by the daemon to create
/// directories and write files; without validation a malicious or
/// careless config could redirect the privileged daemon's
/// `create_dir_all` / write into any path the parent of which is
/// world-writable. Audit Slice 5 hardening.
fn validate_safe_path(line: usize, key: &str, raw: &str) -> Result<PathBuf, ConfigError> {
    if raw.is_empty() {
        return Err(ConfigError::parse(line, format!("{key}: path is empty")));
    }
    if raw.contains('\0') {
        return Err(ConfigError::parse(
            line,
            format!("{key}: path contains NUL"),
        ));
    }
    let p = PathBuf::from(raw);
    if !p.is_absolute() {
        return Err(ConfigError::parse(
            line,
            format!("{key}: `{raw}` is relative; daemon paths must be absolute"),
        ));
    }
    for c in p.components() {
        if matches!(c, std::path::Component::ParentDir) {
            return Err(ConfigError::parse(
                line,
                format!("{key}: `{raw}` contains `..` (path traversal)"),
            ));
        }
    }
    Ok(p)
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
            g.metrics_textfile = Some(validate_safe_path(line, "metrics-textfile", path)?);
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
            g.bpffs_root = validate_safe_path(line, "bpffs-root", path)?;
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
            g.state_dir = validate_safe_path(line, "state-dir", path)?;
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
            validate_iface_name(line, "attach", iface)?;
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
        "local-prefix" => {
            // Grammar: local-prefix <cidr> via <iface> [arp-scavenge]
            let cidr_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "local-prefix requires a CIDR (e.g. 23.191.200.0/24)")
            })?;
            let via_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "local-prefix requires `via <iface>` after the CIDR")
            })?;
            if via_tok != "via" {
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "local-prefix: expected `via` after the CIDR, got `{via_tok}` \
                         (form: `local-prefix <cidr> via <iface> [arp-scavenge]`)"
                    ),
                ));
            }
            let iface = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "local-prefix: expected an interface name after `via`")
            })?;
            validate_iface_name(line, "local-prefix", iface)?;
            // v0.2.1 issue #32: optional `arp-scavenge` tail flag.
            let mut arp_scavenge = false;
            for tail in rest {
                match tail {
                    "arp-scavenge" => arp_scavenge = true,
                    other => {
                        return Err(ConfigError::parse(
                            line,
                            format!(
                                "local-prefix: unknown tail flag `{other}` \
                                 (only `arp-scavenge` is recognized)"
                            ),
                        ));
                    }
                }
            }
            let p: Ipv4Prefix = cidr_tok
                .parse()
                .map_err(|e: String| ConfigError::parse(line, e))?;
            // Cap arp-scavenge at /22 (≤ 1024 hosts) to avoid kernel
            // gc_thresh3 overflow. Larger prefixes silently fall back to
            // arp-scavenge=false with a config-error so the operator
            // notices.
            if arp_scavenge && p.prefix_len < 22 {
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "local-prefix arp-scavenge requires prefix_len >= 22 (≤ 1024 hosts) \
                         to avoid kernel ARP storms; got /{}",
                        p.prefix_len
                    ),
                ));
            }
            Ok(ModuleDirective::LocalPrefix {
                cidr: p,
                iface: iface.to_string(),
                arp_scavenge,
                line,
            })
        }
        "fallback-default" => {
            // Grammar: fallback-default via <iface> nexthop <ipv4>
            let via_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "fallback-default requires `via <iface> nexthop <ipv4>`",
                )
            })?;
            if via_tok != "via" {
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "fallback-default: expected `via`, got `{via_tok}` \
                         (form: `fallback-default via <iface> nexthop <ipv4>`)"
                    ),
                ));
            }
            let iface = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "fallback-default: expected an iface name after `via`")
            })?;
            validate_iface_name(line, "fallback-default", iface)?;
            let nh_kw = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "fallback-default: expected `nexthop <ipv4>` after iface",
                )
            })?;
            if nh_kw != "nexthop" {
                return Err(ConfigError::parse(
                    line,
                    format!("fallback-default: expected `nexthop`, got `{nh_kw}`"),
                ));
            }
            let nh_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "fallback-default: missing IPv4 nexthop after `nexthop`",
                )
            })?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "fallback-default takes exactly: via <iface> nexthop <ipv4>",
                ));
            }
            let nh: Ipv4Addr = nh_tok
                .parse()
                .map_err(|e| ConfigError::parse(line, format!("bad IPv4 `{nh_tok}`: {e}")))?;
            Ok(ModuleDirective::FallbackDefault {
                iface: iface.to_string(),
                nexthop: nh,
                line,
            })
        }
        "block-prefix" => {
            // Grammar: block-prefix <cidr>
            let cidr = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "block-prefix requires a CIDR"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(line, "block-prefix takes one argument"));
            }
            let p: Ipv4Prefix = cidr
                .parse()
                .map_err(|e: String| ConfigError::parse(line, e))?;
            Ok(ModuleDirective::BlockPrefix { cidr: p, line })
        }
        "mss-clamp" => {
            // v0.2.4+, four grammars accepted:
            //   mss-clamp <mtu>
            //   mss-clamp via <iface> <mtu>
            //   mss-clamp <cidr> <mtu>
            //   mss-clamp <cidr> via <iface> <mtu>
            //
            // Disambiguation: a token containing `/` (CIDR delimiter)
            // is treated as a prefix; the literal `via` introduces an
            // egress-iface scope; otherwise the token is the MSS
            // value. SPEC §4.x.
            let tok1 = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "mss-clamp requires at least an MTU value \
                     (form: `mss-clamp [<cidr>] [via <iface>] <mtu>`)",
                )
            })?;
            let mut prefix: Option<MssClampPrefix> = None;
            let mut iface: Option<String> = None;
            let mss_tok: &str;

            if tok1 == "via" {
                // mss-clamp via <iface> <mtu>
                let iface_tok = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "mss-clamp: expected an iface name after `via`")
                })?;
                iface = Some(iface_tok.to_string());
                mss_tok = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "mss-clamp: expected an MTU value after the iface")
                })?;
            } else if tok1.contains('/') {
                // mss-clamp <cidr> [via <iface>] <mtu>
                if let Ok(p) = tok1.parse::<Ipv4Prefix>() {
                    prefix = Some(MssClampPrefix::V4(p));
                } else if let Ok(p) = tok1.parse::<Ipv6Prefix>() {
                    prefix = Some(MssClampPrefix::V6(p));
                } else {
                    return Err(ConfigError::parse(
                        line,
                        format!(
                            "mss-clamp: cannot parse `{tok1}` as IPv4 or IPv6 CIDR \
                             (form: `mss-clamp [<cidr>] [via <iface>] <mtu>`)"
                        ),
                    ));
                }
                let next_tok = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "mss-clamp: expected `via <iface>` or an MTU value")
                })?;
                if next_tok == "via" {
                    let iface_tok = rest.next().ok_or_else(|| {
                        ConfigError::parse(line, "mss-clamp: expected an iface name after `via`")
                    })?;
                    iface = Some(iface_tok.to_string());
                    mss_tok = rest.next().ok_or_else(|| {
                        ConfigError::parse(line, "mss-clamp: expected an MTU value after the iface")
                    })?;
                } else {
                    mss_tok = next_tok;
                }
            } else {
                // mss-clamp <mtu>
                mss_tok = tok1;
            }

            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "mss-clamp: too many arguments \
                     (form: `mss-clamp [<cidr>] [via <iface>] <mtu>`)",
                ));
            }

            let mss: u16 = mss_tok.parse().map_err(|e| {
                ConfigError::parse(line, format!("mss-clamp: bad MTU `{mss_tok}`: {e}"))
            })?;
            // 88 = TCP/IP minimum (RFC 879/1122, 40-byte v4+TCP
            // header on a 128-byte frame, less than 88 starts breaking
            // assumptions). 65495 = max ethernet payload minus a v4 +
            // TCP header (65535 - 40). Outside this range is almost
            // certainly a config typo.
            if !(88..=65495).contains(&mss) {
                return Err(ConfigError::parse(
                    line,
                    format!("mss-clamp: MTU {mss} out of range [88, 65495]"),
                ));
            }
            Ok(ModuleDirective::MssClamp {
                prefix,
                iface,
                mss,
                line,
            })
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
/// - `bmp <addr>:<port> [require-loc-rib] [allow-remote peer-from <cidr> ...]`
/// - `bgp <addr>:<port> local-as <asn> peer-as <asn> [router-id <ipv4>]
///        [allow-remote peer-from <cidr> ... [peer-ip <ip>]]`
///
/// Unknown kinds become parse errors with an explicit message.
///
/// **Listener authorization.** Non-loopback listen addresses require
/// the explicit `allow-remote` opt-in plus at least one `peer-from
/// <cidr>` entry. Loopback listens with no extra keywords keep the
/// pre-existing config compatible. See [`RouteSourceSpec`].
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
            let mut require_loc_rib = false;
            let mut allow_remote = false;
            let mut peer_from: Vec<ipnet::IpNet> = Vec::new();
            // Peek-driven loop: `require-loc-rib` / `allow-remote`
            // are no-value flags; `peer-from` consumes one trailing
            // CIDR argument.
            while let Some(tok) = rest.next() {
                match tok {
                    "require-loc-rib" => require_loc_rib = true,
                    "allow-remote" => allow_remote = true,
                    "peer-from" => {
                        let cidr_str = rest.next().ok_or_else(|| {
                            ConfigError::parse(
                                line,
                                "route-source bmp: `peer-from` requires a <cidr> argument",
                            )
                        })?;
                        let cidr = cidr_str.parse::<ipnet::IpNet>().map_err(|e| {
                            ConfigError::parse(
                                line,
                                format!("route-source bmp: bad peer-from `{cidr_str}`: {e}"),
                            )
                        })?;
                        peer_from.push(cidr);
                    }
                    other => {
                        return Err(ConfigError::parse(
                            line,
                            format!(
                                "route-source bmp: unknown tail flag `{other}` (known: require-loc-rib, allow-remote, peer-from <cidr>)"
                            ),
                        ));
                    }
                }
            }
            validate_listener_auth(line, "bmp", &addr, allow_remote, !peer_from.is_empty(), false)?;
            Ok(ModuleDirective::RouteSource(RouteSourceSpec::Bmp {
                addr,
                port,
                require_loc_rib,
                allow_remote,
                peer_from,
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
            let mut allow_remote = false;
            let mut peer_from: Vec<ipnet::IpNet> = Vec::new();
            let mut peer_ip: Option<std::net::IpAddr> = None;
            while let Some(key) = rest.next() {
                // `allow-remote` is a no-value flag; everything
                // else takes one argument.
                if key == "allow-remote" {
                    allow_remote = true;
                    continue;
                }
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
                    "peer-from" => {
                        let cidr = value.parse::<ipnet::IpNet>().map_err(|e| {
                            ConfigError::parse(
                                line,
                                format!("route-source bgp: bad peer-from `{value}`: {e}"),
                            )
                        })?;
                        peer_from.push(cidr);
                    }
                    "peer-ip" => {
                        let ip = value.parse::<std::net::IpAddr>().map_err(|e| {
                            ConfigError::parse(
                                line,
                                format!("route-source bgp: bad peer-ip `{value}`: {e}"),
                            )
                        })?;
                        peer_ip = Some(ip);
                    }
                    other => {
                        return Err(ConfigError::parse(
                            line,
                            format!(
                                "route-source bgp: unknown key `{other}` (known: local-as, peer-as, router-id, allow-remote, peer-from, peer-ip)"
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
            validate_listener_auth(
                line,
                "bgp",
                &addr,
                allow_remote,
                !peer_from.is_empty(),
                peer_ip.is_some(),
            )?;
            Ok(ModuleDirective::RouteSource(RouteSourceSpec::Bgp {
                addr,
                port,
                local_as,
                peer_as,
                router_id,
                allow_remote,
                peer_from,
                peer_ip,
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

/// Cross-check that the listen address and the authorization opt-in
/// agree. The rules, same shape for both kinds:
///
/// - Loopback address (127.0.0.0/8, ::1): default-allow with no
///   extra keywords. `allow-remote`, `peer-from`, and `peer-ip` are
///   parse errors because there's no source IP other than 127.x /
///   ::1 to gate on.
/// - Non-loopback address: requires `allow-remote` AND at least one
///   `peer-from <cidr>`. Without those, the listener would accept
///   any TCP connection that reaches the port and inject routes
///   which the audit (May 2026) flagged as the highest-severity
///   finding.
///
/// `addr` is the literal string from the config so the diagnostic
/// can interpolate exactly what the operator typed. Parsing it as
/// an `IpAddr` here is on the hot path of config-load (one call
/// per route-source directive), so the small cost is fine.
fn validate_listener_auth(
    line: usize,
    kind_label: &str,
    addr: &str,
    allow_remote: bool,
    has_peer_from: bool,
    has_peer_ip: bool,
) -> Result<(), ConfigError> {
    // Strip the brackets bird/operators sometimes use around
    // IPv6 endpoints (`[::1]`); `parse_endpoint` returns the raw
    // segment between the brackets unchanged, but a literal `::1`
    // is what reaches us here.
    let parsed = addr
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .map_err(|e| {
            ConfigError::parse(
                line,
                format!("route-source {kind_label}: bad listen address `{addr}`: {e}"),
            )
        })?;
    if parsed.is_loopback() {
        if allow_remote {
            return Err(ConfigError::parse(
                line,
                format!(
                    "route-source {kind_label}: `allow-remote` is only valid with a non-loopback listen address (got loopback `{addr}`)"
                ),
            ));
        }
        if has_peer_from {
            return Err(ConfigError::parse(
                line,
                format!(
                    "route-source {kind_label}: `peer-from` is only valid with `allow-remote` on a non-loopback listen (got loopback `{addr}`)"
                ),
            ));
        }
        if has_peer_ip {
            return Err(ConfigError::parse(
                line,
                format!(
                    "route-source {kind_label}: `peer-ip` is only valid with `allow-remote` on a non-loopback listen (got loopback `{addr}`)"
                ),
            ));
        }
    } else {
        if !allow_remote {
            return Err(ConfigError::parse(
                line,
                format!(
                    "route-source {kind_label}: listen address `{addr}` is not loopback; \
                     add `allow-remote peer-from <cidr>` to bind a routable address. \
                     Without that opt-in the listener has no authentication and would \
                     accept route injections from any reachable host."
                ),
            ));
        }
        if !has_peer_from {
            return Err(ConfigError::parse(
                line,
                format!(
                    "route-source {kind_label}: `allow-remote` requires at least one `peer-from <cidr>` to bound which source IPs may complete the handshake"
                ),
            ));
        }
    }
    Ok(())
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
                allow_remote,
                peer_from,
            } => {
                assert_eq!(addr, "127.0.0.1");
                assert_eq!(port, 6543);
                assert!(!require_loc_rib, "default should be off");
                assert!(!allow_remote, "loopback default does not need opt-in");
                assert!(peer_from.is_empty());
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
                allow_remote,
                peer_from,
                peer_ip,
            } => {
                assert_eq!(addr, "127.0.0.1");
                assert_eq!(port, 1179);
                assert_eq!(local_as, 401401);
                assert_eq!(peer_as, 401401);
                assert_eq!(router_id, Some("103.17.154.7".parse().unwrap()));
                assert!(!allow_remote, "loopback default does not need opt-in");
                assert!(peer_from.is_empty());
                assert!(peer_ip.is_none());
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

    // --- Listener authorization (security audit slice 1) -----------

    #[test]
    fn route_source_bgp_non_loopback_requires_opt_in() {
        // Binding 0.0.0.0 without `allow-remote` is the failure mode
        // the audit (May 2026) flagged as Critical, any TCP-reachable
        // host could speak iBGP and inject routes. Reject at parse
        // time so the operator can't silently misconfigure into the
        // unsafe state.
        let e = parse_module_body("  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1\n")
            .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(
                    message.contains("not loopback") && message.contains("allow-remote"),
                    "msg was: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bmp_non_loopback_requires_opt_in() {
        let e = parse_module_body("  route-source bmp 192.0.2.5:6543\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(
                    message.contains("not loopback") && message.contains("allow-remote"),
                    "msg was: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_allow_remote_with_peer_from_parses() {
        let s = "  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1 allow-remote peer-from 10.0.0.0/24\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bgp {
                addr,
                allow_remote,
                peer_from,
                peer_ip,
                ..
            } => {
                assert_eq!(addr, "0.0.0.0");
                assert!(allow_remote);
                assert_eq!(peer_from.len(), 1);
                assert_eq!(peer_from[0], "10.0.0.0/24".parse::<ipnet::IpNet>().unwrap());
                assert!(peer_ip.is_none());
            }
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_allow_remote_multiple_peer_from_parses() {
        let s = "  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1 \
                 allow-remote peer-from 10.0.0.0/24 peer-from 10.1.0.0/16\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bgp { peer_from, .. } => {
                assert_eq!(peer_from.len(), 2);
            }
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_allow_remote_without_peer_from_errors() {
        let e = parse_module_body(
            "  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1 allow-remote\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("peer-from"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_peer_from_without_allow_remote_on_loopback_errors() {
        // Loopback listen + peer-from is a config contradiction, the
        // ACL has no work to do because all accepted connections come
        // from 127.x. Catching this at parse-time tells the operator
        // their intent is unclear before the daemon starts.
        let e = parse_module_body(
            "  route-source bgp 127.0.0.1:1179 local-as 1 peer-as 1 peer-from 10.0.0.0/24\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("peer-from"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_allow_remote_on_loopback_errors() {
        let e = parse_module_body(
            "  route-source bgp 127.0.0.1:1179 local-as 1 peer-as 1 allow-remote\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("allow-remote"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_peer_ip_pin_parses() {
        let s = "  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1 \
                 allow-remote peer-from 10.0.0.0/24 peer-ip 10.0.0.5\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bgp { peer_ip, .. } => {
                assert_eq!(peer_ip, Some("10.0.0.5".parse().unwrap()));
            }
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_bad_peer_from_errors() {
        let e = parse_module_body(
            "  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1 \
             allow-remote peer-from not-a-cidr\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("peer-from"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_bad_peer_ip_errors() {
        let e = parse_module_body(
            "  route-source bgp 0.0.0.0:1179 local-as 1 peer-as 1 \
             allow-remote peer-from 10.0.0.0/24 peer-ip not-an-ip\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("peer-ip"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bmp_allow_remote_with_peer_from_parses() {
        let s =
            "  route-source bmp 0.0.0.0:6543 allow-remote peer-from 10.0.0.0/24 require-loc-rib\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bmp {
                addr,
                require_loc_rib,
                allow_remote,
                peer_from,
                ..
            } => {
                assert_eq!(addr, "0.0.0.0");
                assert!(require_loc_rib);
                assert!(allow_remote);
                assert_eq!(peer_from.len(), 1);
            }
            other => panic!("expected Bmp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_ipv6_loopback_accepts_default() {
        // The IPv6 loopback (::1) must round-trip the same as 127.x
        // a default-permissive bind that doesn't need allow-remote.
        match extract_route_source("  route-source bgp [::1]:1179 local-as 1 peer-as 1\n") {
            RouteSourceSpec::Bgp { addr, .. } => assert_eq!(addr, "[::1]"),
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    // --- Path validation (audit Slice 5) ----------------------------

    #[test]
    fn global_path_relative_rejected() {
        for key in ["metrics-textfile", "bpffs-root", "state-dir"] {
            let body = format!("global\n  {key} relative/path\n");
            let e = Config::parse(&body).unwrap_err();
            match e {
                ConfigError::Parse { message, .. } => {
                    assert!(
                        message.contains(key) && message.contains("relative"),
                        "{key} → {message}"
                    );
                }
                other => panic!("expected Parse for {key}, got {other:?}"),
            }
        }
    }

    #[test]
    fn global_path_traversal_rejected() {
        let body = "global\n  bpffs-root /sys/fs/bpf/../../../etc\n";
        let e = Config::parse(body).unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains(".."), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    // --- Iface name validation --------------------------------------

    #[test]
    fn attach_iface_with_slash_rejected() {
        let e = parse_module_body("  attach eth0/foo native\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("forbidden"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn attach_iface_too_long_rejected() {
        let too_long = "x".repeat(MAX_IFACE_LEN + 1);
        let e = parse_module_body(&format!("  attach {too_long} native\n")).unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("IFNAMSIZ"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn attach_iface_double_dot_rejected() {
        let e = parse_module_body("  attach .. native\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("reserved"), "msg was: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn local_prefix_iface_sanitized() {
        let e = parse_module_body("  local-prefix 10.0.0.0/24 via has space\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                // "has space", the parser splits on whitespace so the
                // second token is `space`. Either error is acceptable;
                // they both flag a problem.
                assert!(
                    message.contains("local-prefix")
                        || message.contains("whitespace")
                        || message.contains("unknown tail flag"),
                    "msg was: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    // --- Config file size cap ---------------------------------------

    #[test]
    fn config_file_size_cap_rejects_runaway() {
        let td = TempDir::new("config_size_cap");
        let path = td.path.join("packetframe.conf");
        // Write > 1 MiB of comment lines.
        let big = "# pad\n".repeat(200_000);
        std::fs::write(&path, &big).unwrap();
        let e = Config::from_file(&path).unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("cap"), "msg was: {message}");
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

    // --- local-prefix (v0.2.1; SPEC.md §4.11 connected fast-path) ---

    fn extract_local_prefixes(body: &str) -> Vec<(Ipv4Prefix, String)> {
        let m = parse_module_body(body).expect("parse");
        m.directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::LocalPrefix { cidr, iface, .. } => Some((*cidr, iface.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn local_prefix_parses_basic_form() {
        let lp = extract_local_prefixes("  local-prefix 23.191.200.0/24 via br1337\n");
        assert_eq!(lp.len(), 1);
        let (cidr, iface) = &lp[0];
        assert_eq!(cidr.addr, "23.191.200.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(iface, "br1337");
    }

    #[test]
    fn local_prefix_multiple_directives_accumulate() {
        let body = "  local-prefix 23.191.200.0/24 via br1337\n\
                    local-prefix 10.88.1.0/24 via br88\n\
                    local-prefix 10.10.1.0/24 via br0\n";
        let lp = extract_local_prefixes(body);
        assert_eq!(lp.len(), 3);
        let ifaces: Vec<&str> = lp.iter().map(|(_, i)| i.as_str()).collect();
        assert_eq!(ifaces, vec!["br1337", "br88", "br0"]);
    }

    #[test]
    fn local_prefix_missing_via_keyword_errors() {
        let e = parse_module_body("  local-prefix 23.191.200.0/24 br1337\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("expected `via`"), "message was: {message}");
            }
            _ => panic!("expected Parse error, got {e:?}"),
        }
    }

    #[test]
    fn local_prefix_missing_iface_errors() {
        let e = parse_module_body("  local-prefix 23.191.200.0/24 via\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix_missing_cidr_errors() {
        let e = parse_module_body("  local-prefix\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix_extra_arg_errors() {
        let e =
            parse_module_body("  local-prefix 23.191.200.0/24 via br1337 garbage\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("unknown tail flag"), "msg: {message}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn local_prefix_bad_cidr_errors() {
        let e = parse_module_body("  local-prefix 23.191.200.0 via br1337\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix_arp_scavenge_flag_parses() {
        let m = parse_module_body("  local-prefix 23.191.200.0/24 via br1337 arp-scavenge\n")
            .expect("parse");
        let lp = m
            .directives
            .iter()
            .find_map(|d| match d {
                ModuleDirective::LocalPrefix {
                    cidr,
                    iface,
                    arp_scavenge,
                    ..
                } => Some((*cidr, iface.clone(), *arp_scavenge)),
                _ => None,
            })
            .expect("local-prefix");
        assert_eq!(lp.0.prefix_len, 24);
        assert_eq!(lp.1, "br1337");
        assert!(lp.2, "arp-scavenge flag should be set");
    }

    #[test]
    fn local_prefix_arp_scavenge_omitted_defaults_off() {
        let m = parse_module_body("  local-prefix 23.191.200.0/24 via br1337\n").expect("parse");
        let arp = m.directives.iter().find_map(|d| match d {
            ModuleDirective::LocalPrefix { arp_scavenge, .. } => Some(*arp_scavenge),
            _ => None,
        });
        assert_eq!(arp, Some(false));
    }

    #[test]
    fn local_prefix_arp_scavenge_rejects_oversized_prefix() {
        // /16 = 65K hosts, way over the /22 = 1024 cap.
        let e = parse_module_body("  local-prefix 10.0.0.0/16 via br0 arp-scavenge\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(
                    message.contains("requires prefix_len >= 22"),
                    "msg: {message}"
                );
            }
            _ => panic!(),
        }
    }

    #[test]
    fn local_prefix_arp_scavenge_accepts_slash22_boundary() {
        // /22 = 1024 hosts is the boundary, should be allowed.
        let m =
            parse_module_body("  local-prefix 10.0.0.0/22 via br0 arp-scavenge\n").expect("parse");
        assert_eq!(m.directives.len(), 1);
    }

    #[test]
    fn local_prefix_iface_validated_against_sysfs() {
        // Same machinery as `attach`: a non-existent iface in a
        // local-prefix directive must fail validate_interfaces_in.
        let dir = std::env::temp_dir().join(format!(
            "pf-cfg-local-prefix-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("br1337")).unwrap();
        // Note: br88 is deliberately missing.
        let cfg = Config::parse(
            "module fast-path\n  attach br1337 generic\n  \
             local-prefix 23.191.200.0/24 via br1337\n  \
             local-prefix 10.88.1.0/24 via br88\n",
        )
        .expect("parse ok; validation runs separately");
        let err = cfg.validate_interfaces_in(&dir).unwrap_err();
        match err {
            ConfigError::InterfaceMissing { iface, .. } => {
                assert_eq!(iface, "br88");
            }
            other => panic!("expected InterfaceMissing, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- v0.2.1 fallback-default + block-prefix ---

    #[test]
    fn fallback_default_parses_basic_form() {
        let m = parse_module_body("  fallback-default via eth3 nexthop 194.110.60.50\n")
            .expect("parse");
        let fbd = m.directives.iter().find_map(|d| match d {
            ModuleDirective::FallbackDefault { iface, nexthop, .. } => {
                Some((iface.clone(), *nexthop))
            }
            _ => None,
        });
        assert_eq!(
            fbd,
            Some((
                "eth3".to_string(),
                "194.110.60.50".parse::<Ipv4Addr>().unwrap()
            ))
        );
    }

    #[test]
    fn fallback_default_missing_via_errors() {
        let e = parse_module_body("  fallback-default eth3 nexthop 194.110.60.50\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("expected `via`"), "msg: {message}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn fallback_default_missing_nexthop_keyword_errors() {
        let e = parse_module_body("  fallback-default via eth3 194.110.60.50\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("expected `nexthop`"), "msg: {message}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn fallback_default_bad_ipv4_errors() {
        let e = parse_module_body("  fallback-default via eth3 nexthop not-an-ip\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn fallback_default_extra_arg_errors() {
        let e =
            parse_module_body("  fallback-default via eth3 nexthop 1.2.3.4 extra\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn fallback_default_iface_validated_against_sysfs() {
        let dir = std::env::temp_dir().join(format!(
            "pf-cfg-fbd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("eth3")).unwrap();
        let cfg_ok = Config::parse(
            "module fast-path\n  attach eth3 generic\n  \
             fallback-default via eth3 nexthop 1.2.3.4\n",
        )
        .expect("parse");
        cfg_ok.validate_interfaces_in(&dir).expect("ok");

        let cfg_bad = Config::parse(
            "module fast-path\n  attach eth3 generic\n  \
             fallback-default via missing0 nexthop 1.2.3.4\n",
        )
        .expect("parse");
        let err = cfg_bad.validate_interfaces_in(&dir).unwrap_err();
        match err {
            ConfigError::InterfaceMissing { iface, .. } => assert_eq!(iface, "missing0"),
            other => panic!("expected InterfaceMissing, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_prefix_parses_basic_form() {
        let m = parse_module_body("  block-prefix 10.0.0.0/8\n").expect("parse");
        let bp = m
            .directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::BlockPrefix { cidr, .. } => Some(*cidr),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(bp.len(), 1);
        assert_eq!(bp[0].addr, "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(bp[0].prefix_len, 8);
    }

    #[test]
    fn block_prefix_multiple_lines_accumulate() {
        let body = "  block-prefix 10.0.0.0/8\n\
                    block-prefix 172.16.0.0/12\n\
                    block-prefix 192.168.0.0/16\n\
                    block-prefix 100.64.0.0/10\n";
        let m = parse_module_body(body).expect("parse");
        let n = m
            .directives
            .iter()
            .filter(|d| matches!(d, ModuleDirective::BlockPrefix { .. }))
            .count();
        assert_eq!(n, 4);
    }

    #[test]
    fn block_prefix_missing_cidr_errors() {
        let e = parse_module_body("  block-prefix\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn block_prefix_extra_arg_errors() {
        let e = parse_module_body("  block-prefix 10.0.0.0/8 something\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    // --- mss-clamp tests (v0.2.4+) ----------------------------------

    fn extract_mss_clamps(m: &ModuleSection) -> Vec<(Option<MssClampPrefix>, Option<String>, u16)> {
        m.directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::MssClamp {
                    prefix, iface, mss, ..
                } => Some((*prefix, iface.clone(), *mss)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn mss_clamp_global_form() {
        let m = parse_module_body("  mss-clamp 1360\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], (None, None, 1360));
    }

    #[test]
    fn mss_clamp_per_iface_form() {
        let m = parse_module_body("  mss-clamp via eth2 1400\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, None);
        assert_eq!(v[0].1.as_deref(), Some("eth2"));
        assert_eq!(v[0].2, 1400);
    }

    #[test]
    fn mss_clamp_per_prefix_v4() {
        let m = parse_module_body("  mss-clamp 23.191.201.0/24 1280\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v.len(), 1);
        match v[0].0.as_ref().unwrap() {
            MssClampPrefix::V4(p) => {
                assert_eq!(p.addr.octets(), [23, 191, 201, 0]);
                assert_eq!(p.prefix_len, 24);
            }
            other => panic!("expected V4, got {other:?}"),
        }
        assert_eq!(v[0].1, None);
        assert_eq!(v[0].2, 1280);
    }

    #[test]
    fn mss_clamp_per_prefix_v6() {
        let m = parse_module_body("  mss-clamp 2001:db8::/48 1280\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v.len(), 1);
        match v[0].0.as_ref().unwrap() {
            MssClampPrefix::V6(p) => assert_eq!(p.prefix_len, 48),
            other => panic!("expected V6, got {other:?}"),
        }
    }

    #[test]
    fn mss_clamp_prefix_plus_iface() {
        let m = parse_module_body("  mss-clamp 23.191.201.0/24 via eth2 1280\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v.len(), 1);
        assert!(matches!(v[0].0, Some(MssClampPrefix::V4(_))));
        assert_eq!(v[0].1.as_deref(), Some("eth2"));
        assert_eq!(v[0].2, 1280);
    }

    #[test]
    fn mss_clamp_multiple_lines_accumulate() {
        let body = "  mss-clamp 1360\n\
                    mss-clamp via eth2 1400\n\
                    mss-clamp 23.191.201.0/24 1280\n";
        let m = parse_module_body(body).expect("parse");
        assert_eq!(extract_mss_clamps(&m).len(), 3);
    }

    #[test]
    fn mss_clamp_missing_value_errors() {
        let e = parse_module_body("  mss-clamp\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn mss_clamp_missing_iface_after_via_errors() {
        let e = parse_module_body("  mss-clamp via\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn mss_clamp_missing_value_after_iface_errors() {
        let e = parse_module_body("  mss-clamp via eth2\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn mss_clamp_value_below_minimum_errors() {
        // 87 is below the 88 floor.
        let e = parse_module_body("  mss-clamp 87\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    #[test]
    fn mss_clamp_value_above_maximum_errors() {
        // 65496 is above the 65495 ceiling.
        let e = parse_module_body("  mss-clamp 65496\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("out of range"), "got: {msg}");
    }

    #[test]
    fn mss_clamp_ip_without_cidr_errors() {
        // `10.0.0.0` (no `/` slash) → parser treats it as the MSS
        // value position, then sees `1360` as an unexpected extra
        // arg. The error message isn't pretty but the directive is
        // rejected, which is what matters.
        let e = parse_module_body("  mss-clamp 10.0.0.0 1360\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }), "got: {e:?}");
    }

    #[test]
    fn mss_clamp_extra_arg_errors() {
        let e = parse_module_body("  mss-clamp 1360 extra\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn mss_clamp_value_at_minimum_accepted() {
        let m = parse_module_body("  mss-clamp 88\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v[0].2, 88);
    }

    #[test]
    fn mss_clamp_value_at_maximum_accepted() {
        let m = parse_module_body("  mss-clamp 65495\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v[0].2, 65495);
    }
}
