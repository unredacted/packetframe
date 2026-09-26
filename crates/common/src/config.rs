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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

impl LogLevel {
    /// The lowercase spelling: the one [`FromStr`] accepts, the one
    /// `Serialize` emits, and the one a `tracing` filter directive
    /// wants. Kept as one function so those three can't drift.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
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
    // --- vpp-offload module (phase 4). Directive namespace is shared
    // across module sections; these names are vpp-offload's. ---
    /// `port <iface> cores <n> steer on|off [vlans <id>[,<id>...]]` —
    /// VPP forwarding-domain membership for one physical port (VF +
    /// vfio + VPP interface, usable as egress) plus its steering
    /// state. Membership is all-or-nothing across the domain (a
    /// steered packet's best path may egress any port); `steer` is
    /// the per-port canary lever.
    ///
    /// `vlans` declares the 802.1Q tags steered ingress arrives with
    /// on a trunk port; the module creates a matching dot1q
    /// subinterface per id at attach. Without it, every tagged frame
    /// the MCAM diverts is punted at VPP's ethernet-input before any
    /// routing — measured on the primary 2026-08-14 (w20): 8.7M
    /// frames in two minutes, all punted, zero forwarded. Untagged
    /// ingress (an access port, or the PVID) needs no declaration.
    ///
    /// `cores` is how many VPP workers poll this port's rx queues
    /// (one queue per worker). `cores 0` gives the port no worker of
    /// its own: ONE shared worker is added for all such ports
    /// ([`vpp_worker_count`]), and the first `cores 0` port's queue is
    /// polled there. VPP's octeon driver places queues round-robin in
    /// creation order and offers no way to move them, so any further
    /// `cores 0` ports' queues wrap onto the dedicated workers — see
    /// the module's `cores::rx_placement_plan`. For egress-only members
    /// — while a port is unsteered its VF receives ~nothing, yet a
    /// dedicated worker would busy-poll a core for it.
    /// A `cores 0` port cannot `steer on` (validation refuses it);
    /// giving it a core of its own is restart-only, like every `cores`
    /// change.
    ///
    /// `direction` overrides the global `steer-direction` for this
    /// port's rules. The split a service-edge box wants: `src` on the
    /// service trunk (outbound rides VPP), `dst` on the transit ports
    /// (inbound rides VPP once `local-route` delivery exists). Absent
    /// = the global setting.
    VppPort {
        iface: String,
        cores: u16,
        steer: bool,
        vlans: Vec<u16>,
        /// `vlans all`: the port's subinterfaces follow the tagged VLANs
        /// the kernel bridge carries on it, including ones added while
        /// VPP runs. `vlans` is empty when this is set.
        vlans_all: bool,
        direction: Option<VppSteerDirection>,
        line: usize,
    },
    /// `vpp-binary <path>` — override the probed VPP binary path.
    VppBinary(String),
    /// `expected-routes <n>` — sizing input: v4+v6 table + headroom.
    /// The independent variable for VPP heap + hugepage arithmetic.
    ExpectedRoutes(u64),
    /// `hugepages <n>` — default-size hugepages to reserve at attach.
    /// Must be ≥ the minimum derived from `expected-routes`; the
    /// renderer errors at load otherwise.
    VppHugepages(u32),
    /// `steer-capacity <n>` — the ntuple rule table each steerable
    /// member port should hold, raised at attach through the driver's
    /// `mcam_count` devlink parameter where it has one. A request, not
    /// a promise: the table the NIC reports afterwards is the budget.
    /// Never shrinks a table. Bounded by [`VPP_MAX_STEER_CAPACITY`].
    VppSteerCapacity(u16),
    /// `loopback-address <ip>/<len>` — the address VPP's loopback holds,
    /// which every member port is unnumbered to.
    ///
    /// Not derivable, which is why it is configuration. A member port
    /// forwards nothing until IPv4 is enabled on it (traced on hardware
    /// 2026-08-07: frames reach `ip4-not-enabled` and are dropped), and
    /// the scheme that works is one loopback carrying the router address
    /// with the members unnumbered to it. Which address that should be
    /// is a per-box decision — the reference primary has a different
    /// address on each of four member ports and only one loopback — and
    /// it is also what sources ICMP, so PMTUD's frag-needed is only
    /// correct if an operator chose it deliberately.
    VppLoopbackAddress(Ipv4Prefix),
    /// `steer-exempt <ip>/<len>` — a destination whose traffic stays on
    /// the kernel path while steering is on, installed as a
    /// higher-priority MCAM rule delivering to the PF. Repeatable.
    ///
    /// For the addresses that terminate ON this router: the gateway
    /// IPs of steered service VLANs above all. Without them,
    /// src-steered traffic destined to the router — monitoring
    /// replies, unicast DHCP renewals, management from the service
    /// net — matches the steer rules and dies in VPP, which has no
    /// local delivery. Measured on the primary (w23, 2026-08-14):
    /// 110,917 such packets blackholed in five steered minutes.
    /// Broadcast and multicast exemptions are built in and need no
    /// directive.
    VppSteerExempt(Ipv4Prefix),
    /// `require-table-complete on|off` — whether a first steer waits
    /// for the route mirror to be confirmed converged against bird.
    ///
    /// Default `on`. `off` is for deployments with no authority to
    /// compare against — the shadow has no bird of its own — and it
    /// means the operator owns the completeness judgement instead.
    VppRequireTableComplete(bool),
    /// `steer-direction src|dst|both` — which side of the packet the
    /// MCAM rules match, per allowlisted prefix.
    ///
    /// Default `both`, which is right for pure-transit deployments
    /// where VPP can forward either direction of a flow. `src` is for
    /// service-edge deployments staging toward bidirectional: outbound
    /// (src ∈ the service prefix) rides VPP's full-table best path
    /// while inbound stays on the eBPF tier. Steering `dst` (or the
    /// `both` default) toward locally terminated prefixes additionally
    /// requires `local-route` coverage — VPP must be able to DELIVER
    /// what a dst rule diverts, and validation refuses the config
    /// otherwise rather than letting a canary discover the blackhole.
    /// The split-tier flow halves are safe under the stateless-transit
    /// invariant that steering already requires — no different from
    /// ECMP asymmetry. Per-port override: the `direction` tail on a
    /// `port` line.
    ///
    /// Hot-reloadable: the steering target is rebuilt from config on
    /// every `packetframe reconfigure`, and `steer` is a reconcile, so
    /// a direction change installs/removes exactly the delta.
    VppSteerDirection(VppSteerDirection),
    /// `local-route <v4-cidr> port <iface> vlan <vid>` — a locally
    /// terminated prefix VPP must DELIVER, not forward: an attached
    /// route onto the member port's dot1q subinterface, with kernel
    /// neighbours on the backing bridge mirrored as VPP static
    /// neighbours. Repeatable; restart-only.
    ///
    /// Two things hang off it. First, delivery: without it, steered
    /// traffic destined to the prefix dies in VPP (`null-node`), which
    /// is why dst-direction steering refuses to load unless every
    /// steerable local prefix has one. Second, shadowing: the route
    /// mirror's BGP view of the prefix is SKIPPED — the kernel tier
    /// delivers to bridge hosts before its FIB lookup, so a mirrored
    /// route inside a local prefix (the reference primary carries a
    /// host route as `unreachable` in bird) would blackhole in VPP
    /// what the kernel delivers fine. The prefix must match a
    /// fast-path `local-prefix` (same tier-agreement philosophy as
    /// the membership rule; the kernel bridge device comes from its
    /// `via`), and the port must declare the vlan in its `vlans`.
    VppLocalRoute {
        prefix: Ipv4Prefix,
        iface: String,
        vlan: u16,
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
    /// IPv6 counterpart of [`Self::LocalPrefix`]: `local-prefix6 <cidr>
    /// via <iface>`. The resolver synthesizes per-/128 routes from the
    /// kernel's NDP neighbour table, nexthop = the host itself, so the
    /// /128 wins the `FIB_V6` LPM walk over any covering route.
    ///
    /// Deliberately has **no** `arp-scavenge` counterpart. Enumeration
    /// is the wrong tool for IPv6 at any cap: SLAAC (RFC 4862) and
    /// stable-privacy addressing (RFC 7217) scatter host addresses
    /// across the full 64-bit interface-identifier space, so a swept
    /// range would match essentially no autoconfigured host. The hosts a
    /// sweep *could* find (hand-numbered `::1..::ff` servers) are
    /// statically configured and actively talking, which means they are
    /// already in the neighbour table that reactive seeding reads. See
    /// `docs/runbooks/custom-fib.md`.
    ///
    /// Requires a matching `allow-prefix6`: the allowlist is consulted
    /// before the FIB lookup, so a /128 in `FIB_V6` does nothing if the
    /// covering prefix isn't allowlisted. Restart-only, like its v4
    /// sibling; SIGHUP does not reconcile it.
    LocalPrefix6 {
        cidr: Ipv6Prefix,
        iface: String,
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
    /// `fib-cache on|off` — destination cache in front of the custom
    /// FIB LPM lookups (default off; an experiment with an explicit
    /// kill criterion, see docs). Caches the FibValue keyed on the
    /// full destination address; invalidated globally on every route
    /// change via a generation counter owned by the FibProgrammer.
    /// Only meaningful under `forwarding-mode custom-fib`; parsed and
    /// inert otherwise (warned at apply time). SIGHUP-reconcilable.
    FibCache(bool),
    /// `coalesce [rx-usecs <n>] [rx-frames <n>] [tx-usecs <n>]
    /// [tx-frames <n>]` — NIC interrupt coalescing applied to every
    /// interface this module attaches (never to one it does not), via
    /// `SIOCETHTOOL` get → merge → set → read back. Unnamed parameters
    /// keep the driver's value. The prior values are recorded in
    /// `<state-dir>/coalesce.json` and written back by `detach`. A
    /// driver that refuses is a WARN, never an attach failure: this is
    /// a performance knob. **Restart-only** (applied at attach, like
    /// `attach` itself); a reload that edits it is refused by name.
    /// The numbers are platform-tuned — see the generic-mode
    /// performance runbook for the measurement behind the example.
    Coalesce {
        spec: crate::ethtool::CoalesceSpec,
        line: usize,
    },
    /// `bridge-resolve auto|on|off` — bridge egress short-circuit
    /// (SPEC §4.7 extension). When the FIB resolves a nexthop whose
    /// egress device is a Linux bridge whose **single forwarding
    /// member** is a VLAN subinterface (`br1337` → `switch0.1337` →
    /// `switch0`), the loader installs a `VLAN_RESOLVE` entry keyed on
    /// the *bridge* ifindex so the datapath tags and redirects straight
    /// to the underlying device, skipping the software bridge traversal
    /// and the subif device. The wire frame is identical to what the
    /// bridge stack would emit; multi-member bridges never qualify
    /// (picking a port needs the FDB, which the datapath can't consult).
    /// `Auto` (default) installs wherever discovery proves the shape;
    /// `On` is accepted as a synonym for `Auto` (there is nothing to
    /// force — an unprovable topology stays on the kernel path);
    /// `Off` disables installation and is the SIGHUP-able rollback.
    BridgeResolve(ToggleAutoOnOff),
    /// `fdb-pin auto|on|off` — FDB-pinned direct-to-port egress
    /// (v0.2.9). Extends the bridge egress short-circuit one hop
    /// further: when a short-circuited chain's underlying device is
    /// itself a multi-member bridge (`br1337` → `switch0.1337` →
    /// `switch0` over `eth0/4/5`), the NeighborResolver consults
    /// `switch0`'s FDB for each nexthop MAC and pins the nexthop's
    /// egress to the specific member port + VID, skipping the bridge
    /// transmit path (FDB lookup, ebtables, the egress qdisc, and the
    /// AF_PACKET tap walk) entirely. Pins invalidate live on AF_BRIDGE
    /// FDB events (MAC move, age-out) and fall back to the bridge
    /// path whenever the FDB has no answer. Requires `bridge-resolve`
    /// active (the pin extends that proof); no-op otherwise. `Auto`
    /// (default) = pin wherever provable; `On` = synonym for `Auto`;
    /// `Off` = never pin. **Restart-only** (attach-time-bound, like
    /// `local-prefix`): the chain snapshot and the FDB subscription
    /// live in the resolver, which is constructed at attach. Editing
    /// this directive and reloading leaves the running state
    /// untouched.
    FdbPin(ToggleAutoOnOff),
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
    /// Which authority the integrity checker cross-checks the mirror
    /// against — the thing that decides whether "the mirror disagrees
    /// with the RIB" is a real alarm or a comparison against the wrong
    /// reference. See [`IntegrityAuthoritySpec`]. Absent ⇒ `Birdc` with
    /// the default path, which is the fleet's shape and preserves
    /// every existing config.
    IntegrityAuthority(IntegrityAuthoritySpec),
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
    // --- guard module (tc-egress frame policer). Directive namespace
    // is shared across module sections; these names are guard's. ---
    /// `interface <iface>` — the guard attach set: one tc-egress
    /// cls_bpf classifier per listed interface. **Restart-only**, like
    /// fast-path's `attach`: the filter and the expected-MAC snapshot
    /// are attach-time-bound. An `interface` line with no class rules
    /// naming it is refused at load (a policer that polices nothing
    /// would attach and report healthy — a silent no-op).
    GuardInterface {
        iface: String,
        line: usize,
    },
    /// `arp-ns-ratelimit <iface> rate <n>/<dur> [burst <m>] [monitor]`
    /// — per-target token bucket over egress ARP requests and ICMPv6
    /// Neighbor Solicitations: `n` frames per `dur` **per target
    /// address**, with up to `burst` back-to-back (default: `n`).
    /// Legitimate kernel resolution (up to 3 probes 1 s apart per
    /// attempt) passes; a firmware daemon re-probing the same targets
    /// forever clamps to the configured rate. `monitor` counts
    /// would-drops without enforcing. Hot-reloadable: SIGHUP rewrites
    /// the per-ifindex config map; bucket state is deliberately not
    /// flushed (stale deadlines converge within one old-burst window).
    GuardArpNsRatelimit {
        iface: String,
        rate: u32,
        per: Duration,
        burst: u32,
        monitor: bool,
        line: usize,
    },
    /// `bcast-mcast-ratelimit <iface> rate <n>/<dur> [burst <m>]
    /// [monitor]` — coarse per-interface token bucket over any egress
    /// frame with the dst-MAC I/G bit set that no earlier guard class
    /// terminated (ARP replies/GARP, MLD, LLC/BPDUs, the next noisy
    /// daemon). Hot-reloadable, same reload semantics as
    /// `arp-ns-ratelimit`.
    GuardBcastMcastRatelimit {
        iface: String,
        rate: u32,
        per: Duration,
        burst: u32,
        monitor: bool,
        line: usize,
    },
    /// `lldp <iface> drop|monitor` — egress LLDP (ethertype 0x88cc).
    /// The action is mandatory: `drop` enforces, `monitor` counts
    /// would-drops. Hot-reloadable. Note LLDP's dst MAC is multicast,
    /// so with this class disabled LLDP still lands in
    /// `bcast-mcast-ratelimit`'s budget.
    GuardLldp {
        iface: String,
        monitor: bool,
        line: usize,
    },
    /// `foreign-src <iface> drop|monitor` — drop any egress frame
    /// whose source MAC is not the interface's own (the "one MAC per
    /// member per VLAN" invariant IX port security enforces). The
    /// expected MAC is read from the interface at attach —
    /// self-referential, so an HA role change needs no config edit,
    /// but a MAC change on a live interface needs a restart. In
    /// `monitor` the frame is counted and **continues** through the
    /// remaining classes (a foreign-MAC ARP storm must still hit the
    /// ARP limiter). Hot-reloadable (action only).
    GuardForeignSrc {
        iface: String,
        monitor: bool,
        line: usize,
    },
    // --- neigh-snoop module (passive ARP/ND neighbour snooper). Shared
    // directive namespace; these names are neigh-snoop's. `interface`
    // already belongs to guard, hence `bridge`. ---
    /// `bridge <iface> [ix-mode]` — a bridge to snoop. **Restart-only**
    /// (the capture socket and the persisted-table file are bound to
    /// the name at attach). Tracked by *name*: the platform daemon
    /// destroys and recreates bridges on provision, so an absent
    /// bridge is not a startup error — the module waits for it.
    /// `ix-mode` additionally tells fast-path's neighbour resolver to
    /// stop issuing its own broadcast probes for nexthops routed via
    /// this bridge (custom-fib only; inert under kernel-fib).
    SnoopBridge {
        iface: String,
        ix_mode: bool,
        line: usize,
    },
    /// `prefix <iface> <cidr>` — an address range the snooper may
    /// learn on that bridge. Repeated; v4 and v6 both accepted; a
    /// bridge with zero prefixes is refused (an empty allowlist learns
    /// nothing and reports healthy). `/0` is refused. Hot-reloadable.
    SnoopPrefix {
        iface: String,
        cidr: ipnet::IpNet,
        line: usize,
    },
    /// `deny-mac <mac>` — never learn or install this hardware address
    /// (an HA standby, the aggregation switch). Each bridge's own MAC
    /// is denied implicitly. Repeated; hot-reloadable.
    SnoopDenyMac {
        mac: [u8; 6],
        line: usize,
    },
    /// `peer <iface> <ip> [<ip>...] [route-server]` — one router on the
    /// fabric and every address it uses there. Configured peers
    /// produce a `never_heard` health set and one INFO line the first
    /// time each is learned. Because the exchange enforces one MAC per
    /// member port, a MAC learned for any address on the line is
    /// installed for the others too (how a route server's v6 global
    /// gets a MAC when it only ever sources NS from link-local).
    /// `route-server` marks a router whose received routes feed the
    /// route-server coverage measurement. Hot-reloadable.
    SnoopPeer {
        iface: String,
        addrs: Vec<IpAddr>,
        route_server: bool,
        line: usize,
    },
    /// `persist-dir <path>` — where `<bridge>.json` learned-table files
    /// live. Default `<state-dir>/neigh-cache`. **Restart-only**.
    SnoopPersistDir {
        path: PathBuf,
        line: usize,
    },
    /// `seed-max-age <N>d` — persisted entries not heard for longer are
    /// dropped from the file and never re-seeded. Default 14d. Hot.
    SnoopSeedMaxAge {
        max_age: Duration,
        line: usize,
    },
    /// `install-rate <n>/<dur>` — kernel neighbour writes, daemon-wide
    /// and shared round-robin across bridges, so a boot-time seed does
    /// not stall the netlink socket other daemons share. Default 50/1s.
    /// Hot.
    SnoopInstallRate {
        rate: u32,
        per: Duration,
        line: usize,
    },
    /// `table-max <n>` — learned entries per bridge; least recently
    /// seen is evicted when full. Default 4096. Hot (a shrink evicts).
    SnoopTableMax {
        max: u32,
        line: usize,
    },
    /// `coverage-interval <N>s` — how often the kernel-route next-hop
    /// coverage is recomputed per bridge. Default 60s. Hot.
    SnoopCoverageInterval {
        interval: Duration,
        line: usize,
    },
    /// `frr-gate v4 <list> v6 <list> [interval <N>s] [remove-after <N>s]`
    /// — enable reconciling FRR's two runtime next-hop prefix-lists
    /// (the dynamic half of the IX next-hop gate) from the kernel
    /// mirror through `vtysh`. Presence and list names are
    /// **restart-only**; interval and remove-after are hot.
    SnoopFrrGate {
        v4_list: String,
        v6_list: String,
        interval: Duration,
        remove_after: Duration,
        line: usize,
    },
    /// `rs-coverage-interval <N>s` — how often each `route-server`
    /// peer's received routes are dumped to measure how many of its
    /// prefixes are still demoted. Default 300s: the dump is large (one
    /// JSON object per received prefix), so the floor is for tests, not
    /// for production. Hot.
    SnoopRsCoverageInterval {
        interval: Duration,
        line: usize,
    },
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
/// What the integrity checker treats as the authority for the mirror.
///
/// The checker compares packetframe's FIB mirror against an authority
/// and calls the difference "drift". The only authority it ever knew
/// was a local `birdc`, hardcoded — which is correct on a box whose own
/// bird feeds the mirror, and simply wrong on a box fed from somewhere
/// else. The shadow is the second kind: its route source is the
/// PRIMARY's bird dialing in over TCP, so the local bird holds 19
/// prefixes while the mirror holds 1.3M, and every check reported a
/// 6.8-million-percent "drift" against a RIB that was never the feed.
///
/// So the authority is now a stated deployment fact rather than a
/// guess. It is deliberately NOT inferred from the route-source address
/// (loopback-vs-remote), because that is the same correlation-for-fact
/// substitution that produced the bug: the operator knows which daemon
/// feeds the box; make them say it.
///
/// Two authorities exist today, and the roadmap has two more that need
/// no external process and work with any BGP daemon — **feed
/// accounting** (the listener's own live-prefix count against the
/// mirror) and **BMP stats reports** (RFC 7854 Loc-RIB counts in-band).
/// Neither is built; the enum is left open for them rather than shimmed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum IntegrityAuthoritySpec {
    /// A local `birdc` is the authority. `None` path ⇒ the default
    /// (`/usr/sbin/birdc`). This is the value assumed when the directive
    /// is absent, so the fleet's existing configs behave unchanged.
    Birdc { path: Option<PathBuf> },
    /// Nothing local can attest completeness: the mirror is fed from a
    /// route source elsewhere, so no comparison is run. The
    /// `fib-integrity` row reports this as informational rather than an
    /// alarm, and the second tier treats the mirror as unattested —
    /// which is why `require-table-complete on` is refused alongside it,
    /// there being no authority for it to require.
    None,
    /// A local FRR is the authority, read through `vtysh`.
    ///
    /// Deliberately a STRONGER guarantee than [`Self::Birdc`], which is
    /// count-only. FRR's per-AF prefix count alone cannot distinguish a
    /// converged table from one still filling from upstream — both ends
    /// grow together and the counts agree the whole way — so this
    /// variant also requires End-of-RIB from every declared upstream,
    /// scoped to the current session.
    ///
    /// Measured on the reference lab gateway (FRR 10.1.2, 2026-09-22):
    /// two seconds after `clear bgp`, the peer read `Established` with
    /// `endOfRibRecv=false`. Gating on session state alone would have
    /// called that table complete.
    Frr {
        /// `vtysh` path. `None` ⇒ `/usr/bin/vtysh`.
        vtysh: Option<PathBuf>,
        /// The upstream peers whose End-of-RIB must have arrived for
        /// their current session before the mirror can be called
        /// complete, each with the families that session carries.
        ///
        /// Declared, never inferred: only the operator knows which
        /// sessions carry the table as opposed to being a consumer of
        /// it. PF's own downstream session must NOT appear here — it is
        /// the thing being attested, and listing it would have the
        /// authority wait on its own answer.
        upstreams: Vec<AuthorityUpstream>,
        /// Seconds between checks. `None` ⇒ the checker's default (300).
        ///
        /// Configurable because the interval is not only a test-loop
        /// annoyance: it IS the recovery time after every session flap.
        /// A revocation is sticky and clears only on the next clean
        /// check, so at 300 s a single flap costs 5–10 minutes of
        /// ineligibility — measured on the lab rig, 2026-09-22 — and on
        /// this platform every FRR config upload flaps every session.
        ///
        /// Bounded by [`FRR_INTERVAL_SECS`]. Restart-only like the rest of
        /// the spec: `restart_only_delta` compares the whole value.
        interval_secs: Option<u64>,
    },
}

/// Allowed range for `integrity-authority frr interval`.
///
/// The floor is what one check costs. Every tick runs a `vtysh` per
/// counted family plus the running-config and one per upstream, each
/// with a 10 s timeout, and `show bgp <afi> unicast statistics` walks
/// the whole table — cheap at the lab rig's 69k routes, unmeasured at a
/// full one. Below ten seconds a slow tick simply runs back to back.
///
/// The ceiling comes from the report-age limit the steering gate
/// applies: a report older than `STEER_MAX_REPORT_AGE` (900 s) is
/// `Stale` and refuses. **One failed check must not be able to age the
/// retained report out**, and the arithmetic for that is not "interval
/// below the limit". The checker sleeps a full interval after every
/// attempt, failed or not, so from a report at t=0 the next attempt
/// lands at about `interval + check time` and — if that one fails, which
/// retains the old report — the one after it at twice that. That second
/// attempt has to land before t=900.
///
/// An earlier revision allowed two thirds of the limit (600 s) and said
/// it left room for one failed check. It did not: attempt at ~600,
/// failure, retry at ~1200, and a healthy box refused every steer from
/// 900 to 1200 (review finding, PR #236). A third of the limit — 300 s,
/// which is also the default — leaves 150 s for the two checks
/// themselves. Slower than the default buys nothing anyway: it only
/// lengthens the flap cost and the staleness exposure together.
pub const FRR_INTERVAL_SECS: std::ops::RangeInclusive<u64> =
    10..=(crate::fib::STEER_MAX_REPORT_AGE.as_secs() / 3);

/// One declared upstream and the families its session carries.
///
/// Families are **per upstream and mandatory**, which an earlier
/// revision got wrong in two ways at once by making them a single
/// global list that defaulted to `v4,v6`:
///
/// - On an IPv4-only box the default silently declared IPv6 as well.
///   `parse_total_prefixes` refuses a missing `ipv6Unicast` array and a
///   missing IPv6 End-of-RIB reads as not-ready, so a perfectly valid
///   deployment could never attest anything and
///   `require-table-complete` would defer forever — the exact failure
///   this whole variant exists to prevent, introduced by its own
///   default.
/// - Where IPv4 and IPv6 arrive over SEPARATE sessions, one global list
///   is a Cartesian product: the v4-only peer permanently lacks IPv6
///   End-of-RIB and the v6-only peer permanently lacks IPv4. A common
///   dual-stack arrangement was simply not expressible.
///
/// There is no safe default here, because the right answer is a fact
/// about the operator's topology that nothing in the config can see. So
/// it is required rather than guessed, the way `upstream` itself
/// already is. The families the *comparison* counts are the union of
/// these — derived, because the mirror holds exactly what the upstreams
/// carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityUpstream {
    pub addr: IpAddr,
    /// Non-empty, enforced at parse.
    pub families: Vec<AuthorityFamily>,
}

/// An address family the FRR authority counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AuthorityFamily {
    V4,
    V6,
}

impl AuthorityFamily {
    /// The `show bgp <this> unicast ...` token.
    pub fn afi(self) -> &'static str {
        match self {
            AuthorityFamily::V4 => "ipv4",
            AuthorityFamily::V6 => "ipv6",
        }
    }

    /// The key FRR uses for this family in its JSON output
    /// (`statistics` keys its array by it; `gracefulRestartInfo` keys
    /// the per-AF block by it).
    pub fn json_key(self) -> &'static str {
        match self {
            AuthorityFamily::V4 => "ipv4Unicast",
            AuthorityFamily::V6 => "ipv6Unicast",
        }
    }
}

impl IntegrityAuthoritySpec {
    /// Whether a reload may move a running daemon from `self` to `new`.
    ///
    /// It may not: the directive is read once, when the route
    /// controller starts and decides whether to spawn a checker and
    /// with which `birdc`. A pure function over two values, mirroring
    /// `VppOffloadConfig::restart_only_delta`, so the rule is testable
    /// without an attach, a BPF object, or a running checker — the
    /// module-side caller supplies the "is a controller actually
    /// running" half.
    ///
    /// Refused rather than silently ignored because this is the
    /// directive an operator edits *because a health line told them
    /// to*: `integrity-authority none` is what the authority-mismatch
    /// remedy recommends, and a reload that accepts it while the
    /// checker keeps using the old authority leaves the false alarm
    /// standing and the operator believing they fixed it.
    pub fn restart_only_delta(&self, new: &Self) -> Result<(), String> {
        if self == new {
            return Ok(());
        }
        Err(format!(
            "`integrity-authority` changed ({self:?} → {new:?}) and it is read once, when \
             the route controller starts: a reload cannot move the running checker onto a \
             different authority. Restart the daemon for it"
        ))
    }
}

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
        /// When true, the controller installs a `local <addr>/32
        /// dev lo` kernel route (AnyIP) before binding, and removes
        /// it on shutdown. This makes a *phantom* listen address —
        /// one no interface owns — bindable and locally deliverable.
        ///
        /// Exists for daemons that refuse to peer with an address
        /// their host owns: FRR rejects `neighbor <addr>` for any
        /// interface-owned address at config time ("Can not
        /// configure the local system as neighbor") and cannot
        /// complete a session over loopback (zebra treats 127/8 as
        /// martian, so NHT never resolves and `nexthop_set` finds
        /// no owning interface). The phantom address sidesteps both:
        /// FRR sees an ordinary connected neighbor, packetframe
        /// answers on it. Requires `allow-remote` (the address is
        /// by definition not loopback) and is v4-only today, like
        /// the router-id defaulting it composes with.
        anyip: bool,
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

/// Which side of the packet MCAM steering rules match. See
/// [`ModuleDirective::VppSteerDirection`] for the deployment reasoning.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VppSteerDirection {
    Src,
    Dst,
    #[default]
    Both,
}

impl FromStr for VppSteerDirection {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "src" => Ok(Self::Src),
            "dst" => Ok(Self::Dst),
            "both" => Ok(Self::Both),
            other => Err(format!(
                "steer-direction expects src|dst|both, got `{other}`"
            )),
        }
    }
}

impl std::fmt::Display for VppSteerDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Src => "src",
            Self::Dst => "dst",
            Self::Both => "both",
        })
    }
}

/// VPP worker threads a vpp-offload config needs, from each `port`
/// line's `cores` in any order.
///
/// Every port's `cores`, summed, plus ONE shared worker when any port
/// declares `cores 0` — the worker the first such port's queue lands
/// on. Here, in common, rather than in the module, so the
/// feasibility probe (built with or without the module) and attach
/// derive the same core map from the same arithmetic.
pub fn vpp_worker_count<I: IntoIterator<Item = u16>>(cores: I) -> u32 {
    let mut dedicated = 0u32;
    let mut any_shared = false;
    for c in cores {
        dedicated += u32::from(c);
        any_shared |= c == 0;
    }
    dedicated + u32::from(any_shared)
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
    /// tc-ingress datapath (Phase T): sched_cls classifiers on a
    /// clsact qdisc instead of XDP. For hosts forced into xdp-generic
    /// (e.g. rvu-nicpf pre-6.8), this avoids generic XDP's per-packet
    /// headroom realloc + GRO linearization. Requires
    /// `forwarding-mode custom-fib` (enforced at attach time); `auto`
    /// never selects tc — it is an explicit per-iface opt-in so
    /// canary rollouts stay operator-controlled.
    Tc,
}

impl FromStr for AttachMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native" => Ok(Self::Native),
            "generic" => Ok(Self::Generic),
            "auto" => Ok(Self::Auto),
            "tc" => Ok(Self::Tc),
            other => Err(format!(
                "unknown attach mode `{other}` (expected native|generic|auto|tc)"
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

impl Ipv4Prefix {
    /// The prefix's network address, i.e. `addr` with host bits cleared.
    ///
    /// Declarations are not required to be aligned: `10.0.0.5/24` is
    /// accepted and treated as `10.0.0.0/24`. Callers that need the
    /// canonical form use this.
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & mask_v4(self.prefix_len))
    }

    /// True iff `ip` falls within this prefix. Host bits in the
    /// declaration are ignored (see [`Self::network`]).
    pub fn contains_addr(&self, ip: Ipv4Addr) -> bool {
        let m = mask_v4(self.prefix_len);
        u32::from(ip) & m == u32::from(self.addr) & m
    }

    /// True iff `inner` is equal to or wholly contained within `self`.
    ///
    /// A longer prefix can never contain a shorter one, so this is
    /// `false` whenever `inner` is less specific than `self`.
    pub fn contains_prefix(&self, inner: &Ipv4Prefix) -> bool {
        self.prefix_len <= inner.prefix_len && self.contains_addr(inner.addr)
    }
}

impl Ipv6Prefix {
    /// The prefix's network address, i.e. `addr` with host bits cleared.
    /// See [`Ipv4Prefix::network`] for the alignment convention.
    pub fn network(&self) -> Ipv6Addr {
        Ipv6Addr::from((u128::from(self.addr) & mask_v6(self.prefix_len)).to_be_bytes())
    }

    /// True iff `ip` falls within this prefix. Host bits in the
    /// declaration are ignored.
    pub fn contains_addr(&self, ip: Ipv6Addr) -> bool {
        let m = mask_v6(self.prefix_len);
        u128::from(ip) & m == u128::from(self.addr) & m
    }

    /// True iff `inner` is equal to or wholly contained within `self`.
    pub fn contains_prefix(&self, inner: &Ipv6Prefix) -> bool {
        self.prefix_len <= inner.prefix_len && self.contains_addr(inner.addr)
    }
}

/// Host-bit mask for an IPv4 prefix length.
///
/// Both ends need guarding: `!0u32 << 32` is a shift-overflow panic in
/// debug, and in release Rust masks the shift amount to `32 & 31 == 0`,
/// yielding `!0` — so a `/0` would silently match only its own exact
/// address instead of everything. The release behavior is the dangerous
/// one because it fails silently.
#[inline]
fn mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        !0
    } else {
        (!0u32) << (32 - prefix_len as u32)
    }
}

/// Host-bit mask for an IPv6 prefix length. Same shift-overflow
/// reasoning as [`mask_v4`], with `!0u128 << 128` as the trap.
#[inline]
fn mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        !0
    } else {
        (!0u128) << (128 - prefix_len as u32)
    }
}

/// True iff `a` could plausibly be a connected host we should
/// synthesize a `/128` FIB entry for.
///
/// The rejected classes all share one property: forwarding a packet to
/// them via `bpf_redirect_map` is either meaningless or actively wrong,
/// so a `/128` naming one wastes a slot in the shared 8192-entry
/// `NEXTHOPS` pool at best and misroutes at worst.
///
/// - **Multicast** (`ff00::/8`): the kernel keeps `NUD_NOARP` neighbour
///   entries for multicast groups with a derived `33:33:xx` MAC, so they
///   look exactly like resolved unicast neighbours to the resolver. They
///   are never `NUD_GC`'d either, so a bad entry would persist for the
///   process lifetime.
/// - **Link-local** (`fe80::/10`): not a routed destination, and the
///   resolver's neighbour cache is keyed by address alone — the same
///   `fe80::` address legitimately exists on several interfaces with
///   different MACs, so any entry would be ambiguous by construction.
/// - **Unspecified / loopback / IPv4-mapped**: never valid on the wire
///   as a forwarded destination. IPv4-mapped would additionally create a
///   second, conflicting route for an address already covered by
///   `FIB_V4`.
///
/// Unique-local (`fc00::/7`) is deliberately **allowed** — it is a
/// legitimate choice for an internal connected segment.
///
/// Predicates are hand-rolled on the octets rather than using
/// `Ipv6Addr::is_unicast_link_local` and friends: `is_global` and
/// `is_unicast` are still nightly-only, so hand-rolling keeps this
/// working on the pinned stable toolchain and testable without any
/// toolchain-feature dependency.
pub fn is_harvestable_v6(a: Ipv6Addr) -> bool {
    let o = a.octets();
    // ff00::/8 multicast
    if o[0] == 0xff {
        return false;
    }
    // fe80::/10 link-local unicast
    if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
        return false;
    }
    // ::ffff:0:0/96 IPv4-mapped
    if o[..10].iter().all(|b| *b == 0) && o[10] == 0xff && o[11] == 0xff {
        return false;
    }
    // :: and ::1
    if a.is_unspecified() || a.is_loopback() {
        return false;
    }
    true
}

/// The address classes [`is_harvestable_v6`] rejects, as prefixes, so a
/// `local-prefix6` declaration can be screened for overlap at parse
/// time. Paired with the operator-facing reason.
const FORBIDDEN_V6_CLASSES: [(Ipv6Prefix, &str); 5] = [
    (
        Ipv6Prefix {
            addr: Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
            prefix_len: 8,
        },
        "multicast (ff00::/8)",
    ),
    (
        Ipv6Prefix {
            addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            prefix_len: 10,
        },
        "link-local (fe80::/10)",
    ),
    (
        Ipv6Prefix {
            addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0),
            prefix_len: 96,
        },
        "IPv4-mapped (::ffff:0:0/96)",
    ),
    (
        Ipv6Prefix {
            addr: Ipv6Addr::UNSPECIFIED,
            prefix_len: 128,
        },
        "the unspecified address (::/128)",
    ),
    (
        Ipv6Prefix {
            addr: Ipv6Addr::LOCALHOST,
            prefix_len: 128,
        },
        "loopback (::1/128)",
    ),
];

/// Reject a `local-prefix6` CIDR that is, or overlaps, an address class
/// that must never be harvested into a `/128`.
///
/// A well-formed global `/64` excludes `ff02::` and `fe80::` on its own
/// via containment, so this exists to catch the copy-paste cases (an
/// operator building the directive from `ip -6 neigh show`, which is
/// mostly `fe80::` addresses) and `::/0`, which would harvest the entire
/// neighbour table.
fn reject_non_harvestable_prefix(line: usize, p: &Ipv6Prefix) -> Result<(), ConfigError> {
    if p.prefix_len == 0 {
        return Err(ConfigError::parse(
            line,
            "local-prefix6: `::/0` is not a valid connected prefix. It would harvest every \
             entry in the neighbour table, including multicast and link-local, and burn one \
             NEXTHOPS slot each. Declare the connected prefix instead (e.g. \
             `local-prefix6 2001:db8:0:1337::/64 via br1337`)",
        ));
    }
    for (class, reason) in FORBIDDEN_V6_CLASSES {
        if class.contains_prefix(p) || p.contains_prefix(&class) {
            return Err(ConfigError::parse(
                line,
                format!(
                    "local-prefix6 {}/{} is or overlaps {reason}, which can never be a \
                     forwarded connected-host destination. Declare the global-unicast \
                     prefix assigned to the segment instead",
                    p.addr, p.prefix_len
                ),
            ));
        }
    }
    Ok(())
}

/// Append a "did you mean the other family?" hint when a CIDR fails to
/// parse for one family but succeeds for the other.
///
/// `local-prefix` and `local-prefix6` are separate keywords, so pasting
/// a v6 CIDR under the v4 directive is the obvious slip. The underlying
/// `FromStr` message is preserved rather than replaced, so a genuinely
/// malformed CIDR still reports precisely what was wrong with it.
fn wrong_family_hint(err: String, tok: &str, directive: &str) -> String {
    let other = match directive {
        "local-prefix" if tok.parse::<Ipv6Prefix>().is_ok() => "local-prefix6",
        "local-prefix6" if tok.parse::<Ipv4Prefix>().is_ok() => "local-prefix",
        _ => return err,
    };
    format!("{err} (did you mean `{other}`?)")
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

/// The largest `steer-capacity` accepted.
///
/// Also the most rule locations vpp-offload will enumerate in one
/// table read, so the two must move together: a table larger than the
/// enumeration buffer is refused rather than read short, and a short
/// read makes occupied slots look free. 256 is ample against a shared
/// classifier pool of ~1,700 free entries measured on the reference
/// NIC (2026-09-24), and far past any exemption list worth writing.
pub const VPP_MAX_STEER_CAPACITY: u16 = 256;

/// Maximum `interface` lines a guard section may declare. Mirrors the
/// BPF `GUARD_CFG` map's capacity
/// (`crates/modules/guard/bpf/src/maps.rs`, `GUARD_CFG_MAX_ENTRIES`):
/// the map holds one entry per guarded interface, and a config that
/// overruns it must be refused before any filter is installed rather
/// than failing mid-attach with the first 64 filters already live.
/// The guard crate's `GuardConfig::from_directives` consumes this
/// same constant, so the two verdicts cannot drift.
pub const GUARD_MAX_INTERFACES: usize = 64;

/// Maximum `bridge` lines a neigh-snoop section may declare. Each
/// bridge costs one AF_PACKET socket, one persisted JSON file and one
/// health row; the bound keeps `status` output and the seed backlog
/// legible. The module crate's `SnoopConfig::from_directives`
/// consumes this same constant, so the two verdicts cannot drift.
pub const NEIGH_SNOOP_MAX_BRIDGES: usize = 16;
/// Subdirectory of `state-dir` used when `persist-dir` is absent.
pub const NEIGH_SNOOP_PERSIST_SUBDIR: &str = "neigh-cache";
/// Defaults shared by the parser, the module crate, `example.conf`
/// prose and the runbook — kept in one place so they cannot drift.
pub const NEIGH_SNOOP_DEFAULT_SEED_MAX_AGE: Duration = Duration::from_secs(14 * 86_400);
pub const NEIGH_SNOOP_DEFAULT_INSTALL_RATE: (u32, Duration) = (50, Duration::from_secs(1));
pub const NEIGH_SNOOP_DEFAULT_TABLE_MAX: u32 = 4096;
pub const NEIGH_SNOOP_DEFAULT_COVERAGE_INTERVAL: Duration = Duration::from_secs(60);
pub const NEIGH_SNOOP_DEFAULT_GATE_INTERVAL: Duration = Duration::from_secs(30);
pub const NEIGH_SNOOP_DEFAULT_GATE_REMOVE_AFTER: Duration = Duration::from_secs(180);
pub const NEIGH_SNOOP_DEFAULT_RS_COVERAGE_INTERVAL: Duration = Duration::from_secs(300);

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

    /// Cross-directive checks for `module fast-path` alone.
    ///
    /// Separate from [`Self::validate_vpp_offload`] because that one
    /// returns immediately when there is no `vpp-offload` section, and
    /// both rules here are about fast-path's own directives. A
    /// fast-path-only config was slipping past them entirely — reaching
    /// the loader, failing to spawn an authority, logging an internal
    /// error and running unattested instead of being refused as
    /// documented (review finding, PR #232).
    pub fn validate_fast_path(&self) -> Result<(), ConfigError> {
        let Some(fp) = self.modules.iter().find(|m| m.name == "fast-path") else {
            return Ok(());
        };

        let frr = fp.directives.iter().find_map(|d| match d {
            ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::Frr {
                upstreams, ..
            }) => Some(upstreams),
            _ => None,
        });
        let Some(upstreams) = frr else {
            return Ok(());
        };

        let source = fp.directives.iter().find_map(|d| match d {
            ModuleDirective::RouteSource(s) => Some(s),
            _ => None,
        });

        // `integrity-authority frr` against a BMP route source is
        // refused, and this is a gap rather than a rule.
        //
        // Two of the authority's three conjuncts are fine over BMP: the
        // per-AF counts and the upstreams' End-of-RIB are read from FRR
        // itself and say nothing about how the mirror is fed. The third
        // is not. Export-policy validation asks whether the session
        // feeding packetframe is narrowed, and over BMP there is no
        // session — what narrows the feed is FRR's own `bmp targets`
        // configuration, a different grammar that nothing on the
        // reference fleet has been measured against. Accepting the
        // combination would mean silently dropping the one conjunct the
        // counts cannot substitute for: at a 1% drift tolerance a filter
        // removing 5,000 prefixes from a million still reads
        // `Converged`.
        //
        // Refused rather than downgraded, because a downgrade is
        // invisible — the operator who wrote `integrity-authority frr`
        // would get the weaker guarantee and a green row.
        if matches!(source, Some(RouteSourceSpec::Bmp { .. })) {
            return Err(ConfigError::parse(
                0,
                "module fast-path has `integrity-authority frr` with a BMP route source. \
                 The FRR authority validates the export policy of the BGP session that \
                 feeds this mirror, and a BMP feed has no such session — what narrows it \
                 is FRR's `bmp targets` configuration, which this release cannot read. \
                 Accepting it would quietly drop the one check the prefix counts cannot \
                 substitute for. Use `route-source bgp` (the production path), or \
                 `integrity-authority birdc` if a local bird is the real authority",
            ));
        }

        // packetframe's own session must not be in the upstream set.
        //
        // The spec's docs say so and the parser cannot enforce it: only
        // here are both the declared upstreams and the listen address in
        // scope. Listing it is circular — the authority would wait for
        // End-of-RIB from the session it is supposed to be attesting,
        // which packetframe never sends, so the peer reads not-ready on
        // every check, eligibility is revoked forever and the
        // completeness gate defers every steer. It parses, it passes
        // feasibility (FRR does know that neighbor), and it is
        // discovered as a rollout that will not start (review finding,
        // PR #232).
        if let Some(RouteSourceSpec::Bgp { addr, .. }) = source {
            // `addr` is the listen address as written; a parse failure
            // here means it is not an IP literal, which the route-source
            // parser has already refused, so there is nothing to check.
            let Ok(ours) = addr.parse::<IpAddr>() else {
                return Ok(());
            };
            if upstreams.iter().any(|u| u.addr == ours) {
                return Err(ConfigError::parse(
                    0,
                    format!(
                        "module fast-path lists {ours} as an `integrity-authority frr \
                         upstream`, but that is packetframe's own `route-source bgp` \
                         listen address — the session being attested. The authority would \
                         wait for End-of-RIB from a session packetframe never sends one \
                         on, so it would read not-ready on every check and no steer would \
                         ever be permitted. List the peers that feed FRR, not the one FRR \
                         feeds"
                    ),
                ));
            }
        }

        Ok(())
    }

    /// vpp-offload cross-section validation (phase 4). Pure config
    /// logic — no sysfs — so it runs everywhere `parse` does.
    ///
    /// Rules (plan v5 "membership vs steering" + allowlist invariant):
    /// - a `vpp-offload` section requires a `fast-path` section (the
    ///   steered-prefix set inherits the fast-path allowlist, and the
    ///   eBPF path is the failover tier);
    /// - if ANY port steers, membership must be all-or-nothing:
    ///   every fast-path `attach` interface needs a `port` line (a
    ///   steered packet's best path may egress any port; a missing
    ///   member would blackhole those destinations in VPP);
    /// - steering requires `forwarding-mode custom-fib` (the full
    ///   table VPP mirrors comes from the custom-FIB route pipeline);
    /// - duplicate `port` lines for one interface are rejected.
    pub fn validate_vpp_offload(&self) -> Result<(), ConfigError> {
        let Some(vpp) = self.modules.iter().find(|m| m.name == "vpp-offload") else {
            return Ok(());
        };
        let fast_path = self.modules.iter().find(|m| m.name == "fast-path");

        let mut ports: Vec<(&String, bool, usize)> = Vec::new();
        for d in &vpp.directives {
            if let ModuleDirective::VppPort {
                iface,
                cores,
                steer,
                line,
                ..
            } = d
            {
                if ports.iter().any(|(i, _, _)| *i == iface) {
                    return Err(ConfigError::parse(
                        *line,
                        format!("duplicate `port {iface}` in module vpp-offload"),
                    ));
                }
                // A `cores 0` port's queue is polled by the worker it
                // shares with every other egress-only member. Steering
                // it would land a port's whole ingress on a worker sized
                // for "receives ~nothing" and shared with others, so it
                // is refused here — which also refuses a SIGHUP that
                // flips such a port on, since reconfigure re-validates
                // the whole file. The fix is a core of its own, and that
                // is a restart: VPP's worker count is fixed at start.
                if *cores == 0 && *steer {
                    return Err(ConfigError::parse(
                        *line,
                        format!(
                            "`port {iface}` has `cores 0` and `steer on`: a port with no \
                             worker of its own cannot take steered traffic (its rx queue \
                             shares one worker with every other `cores 0` port). Give it \
                             `cores 1` — a restart-only change — before steering it"
                        ),
                    ));
                }
                ports.push((iface, *steer, *line));
            }
        }

        // An empty section is a config error, not a staging state.
        // Previously it parsed clean here while `VppOffloadModule::load`
        // rejected it, so `packetframe feasibility` could report PASS
        // with no hint that VPP was configured while `packetframe run`
        // refused the same file. One verdict, at the earliest point
        // that can give it.
        if ports.is_empty() {
            return Err(ConfigError::parse(
                0,
                "module vpp-offload declares no `port` lines; remove the section or give it \
                 at least one port (membership must cover every possible egress port)",
            ));
        }

        // A member port that is not IP-enabled forwards NOTHING, and
        // says nothing about it: the FIB is correct, readback
        // verification passes on it, health reports `fib-synced
        // healthy`, and every packet dies at `ip4-not-enabled`. Observed
        // on hardware 2026-08-07 with 1,053,960 routes installed and
        // verified on 64 probes, forwarding zero. So the address that
        // makes forwarding possible is mandatory the moment a port
        // exists, refused here rather than discovered by a canary.
        if !vpp
            .directives
            .iter()
            .any(|d| matches!(d, ModuleDirective::VppLoopbackAddress(_)))
        {
            return Err(ConfigError::parse(
                0,
                "module vpp-offload has `port` lines but no `loopback-address`; member ports \
                 are unnumbered to a loopback and forward nothing without it — and do so \
                 while reporting healthy. Add e.g. `loopback-address 198.51.100.254/32` \
                 (announced but UNASSIGNED: routable so ICMP/PMTUD works, held by no \
                 kernel interface — VPP answers ARP for it, and a live address starts a \
                 responder war; attach refuses one)",
            ));
        }

        // Duplicate exemptions are refused for the same reason
        // duplicate ports are: each consumes an MCAM slot from a
        // 16-per-port budget, so a pasted-twice line silently halves
        // the room the refusal arithmetic reports.
        let mut exempts: Vec<&Ipv4Prefix> = Vec::new();
        for d in &vpp.directives {
            if let ModuleDirective::VppSteerExempt(p) = d {
                if exempts.iter().any(|e| **e == *p) {
                    return Err(ConfigError::parse(
                        0,
                        format!(
                            "duplicate `steer-exempt {}/{}` in module vpp-offload",
                            p.addr, p.prefix_len
                        ),
                    ));
                }
                exempts.push(p);
            }
        }

        let Some(fp) = fast_path else {
            return Err(ConfigError::parse(
                0,
                "module vpp-offload requires a fast-path section (steered prefixes inherit \
                 its allowlist; the eBPF path is the failover tier)",
            ));
        };

        // local-route structural rules. These hold whether or not
        // anything steers: the attached route and neighbour mirror are
        // installed at attach, so a broken declaration is a broken
        // attach, not a broken canary.
        let mut local_routes: Vec<(&Ipv4Prefix, usize)> = Vec::new();
        for d in &vpp.directives {
            if let ModuleDirective::VppLocalRoute {
                prefix,
                iface,
                vlan,
                line,
            } = d
            {
                for (p, _) in &local_routes {
                    if p.contains_prefix(prefix) || prefix.contains_prefix(p) {
                        return Err(ConfigError::parse(
                            *line,
                            format!(
                                "local-route {}/{} duplicates or overlaps local-route {}/{}: \
                                 one attached route owns a prefix",
                                prefix.addr, prefix.prefix_len, p.addr, p.prefix_len
                            ),
                        ));
                    }
                }
                let port_vlans = vpp.directives.iter().find_map(|d| match d {
                    ModuleDirective::VppPort {
                        iface: pi,
                        vlans,
                        vlans_all,
                        ..
                    } if pi == iface => Some((vlans, *vlans_all)),
                    _ => None,
                });
                let Some((port_vlans, port_vlans_all)) = port_vlans else {
                    return Err(ConfigError::parse(
                        *line,
                        format!(
                            "local-route names port `{iface}` but module vpp-offload has no \
                             `port {iface}` line"
                        ),
                    ));
                };
                // `vlans all` follows the kernel, which decides at attach
                // whether the vid exists; an explicit list must name it.
                if !port_vlans_all && !port_vlans.contains(vlan) {
                    return Err(ConfigError::parse(
                        *line,
                        format!(
                            "local-route {}/{}: `port {iface}` does not declare vlan {vlan} \
                             in its `vlans` list — the dot1q subinterface the attached \
                             route lands on is created from that list",
                            prefix.addr, prefix.prefix_len
                        ),
                    ));
                }
                // Tier agreement: the fallback tier must also deliver
                // this prefix locally (fast-path `local-prefix`), both
                // so a failover cannot change what is delivered and
                // because the kernel bridge device the neighbour
                // mirror watches comes from that directive's `via`.
                let covered = fp.directives.iter().any(|d| {
                    matches!(d, ModuleDirective::LocalPrefix { cidr, .. }
                        if cidr.contains_prefix(prefix))
                });
                if !covered {
                    return Err(ConfigError::parse(
                        *line,
                        format!(
                            "local-route {}/{} is not inside any fast-path `local-prefix`: \
                             local delivery must agree across tiers, and the kernel bridge \
                             device for neighbour mirroring comes from \
                             `local-prefix ... via <dev>`",
                            prefix.addr, prefix.prefix_len
                        ),
                    ));
                }
                local_routes.push((prefix, *line));
            }
        }

        // `require-table-complete on` demands a completeness authority,
        // and `integrity-authority none` declares there is none. The two
        // together are a config that can never permit a first steer: the
        // gate waits for an attestation nothing will ever produce. Caught
        // here rather than discovered as a canary that defers forever
        // (the shadow's 23 h, in the shape an operator could actually
        // configure by accident). `require-table-complete` defaults ON,
        // so this fires whenever `integrity-authority none` is set on a
        // steering box without an explicit `off`.
        let require_complete = vpp
            .directives
            .iter()
            .find_map(|d| match d {
                ModuleDirective::VppRequireTableComplete(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(true);
        let authority_is_none = fast_path.is_some_and(|fp| {
            fp.directives.iter().any(|d| {
                matches!(
                    d,
                    ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::None)
                )
            })
        });
        if require_complete && authority_is_none {
            return Err(ConfigError::parse(
                0,
                "module vpp-offload has `require-table-complete on` (the default) but module \
                 fast-path has `integrity-authority none`: there is no authority to attest \
                 completeness, so the first steer would defer forever. Either name an \
                 authority (`integrity-authority birdc`, or `integrity-authority frr \
                 upstream <ip>` on an FRR-fed box) or opt the gate out \
                 (`require-table-complete off`)",
            ));
        }

        let any_steer = ports.iter().any(|(_, steer, _)| *steer);
        if !any_steer {
            return Ok(()); // membership-only staging state is always valid
        }

        let fwd = fp
            .directives
            .iter()
            .find_map(|d| match d {
                ModuleDirective::ForwardingMode(m) => Some(*m),
                _ => None,
            })
            .unwrap_or_default();
        if fwd != ForwardingMode::CustomFib {
            return Err(ConfigError::parse(
                0,
                "vpp-offload steering requires `forwarding-mode custom-fib` in module \
                 fast-path (VPP mirrors the custom-FIB route pipeline)",
            ));
        }

        for d in &fp.directives {
            if let ModuleDirective::Attach { iface, line, .. } = d {
                if !ports.iter().any(|(i, _, _)| *i == iface) {
                    return Err(ConfigError::parse(
                        *line,
                        format!(
                            "vpp-offload steering is enabled but fast-path attach iface \
                             `{iface}` has no `port` line: membership must cover every \
                             possible egress port before any ingress is steered \
                             (missing members blackhole destinations whose best path \
                             egresses them)"
                        ),
                    ));
                }
            }
        }

        // dst-direction coverage. A dst rule steers inbound INTO VPP;
        // for a locally terminated prefix VPP can only deliver it via
        // a `local-route`. An uncovered local prefix would blackhole
        // 100% of its inbound the moment the port steers (w20 shape),
        // so it is refused at load, not discovered at a canary. Pure
        // transit needs nothing here: a dst-steered packet for a
        // non-local prefix is forwarded via the full table.
        let global_dir = vpp
            .directives
            .iter()
            .find_map(|d| match d {
                ModuleDirective::VppSteerDirection(v) => Some(*v),
                _ => None,
            })
            .unwrap_or_default();
        let dst_port = vpp.directives.iter().find_map(|d| match d {
            ModuleDirective::VppPort {
                iface,
                steer: true,
                direction,
                ..
            } if matches!(
                direction.unwrap_or(global_dir),
                VppSteerDirection::Dst | VppSteerDirection::Both
            ) =>
            {
                Some(iface)
            }
            _ => None,
        });
        if let Some(dst_port) = dst_port {
            let allow4: Vec<&Ipv4Prefix> = fp
                .directives
                .iter()
                .filter_map(|d| match d {
                    ModuleDirective::AllowPrefix4(p) => Some(p),
                    _ => None,
                })
                .collect();
            // Half-open u64 ranges so /0 and broadcast+1 don't wrap.
            let range = |p: &Ipv4Prefix| -> (u64, u64) {
                let start = u64::from(u32::from(p.network()));
                (start, start + (1u64 << (32 - p.prefix_len)))
            };
            for d in &fp.directives {
                let ModuleDirective::LocalPrefix { cidr, line, .. } = d else {
                    continue;
                };
                let steerable = allow4
                    .iter()
                    .any(|a| a.contains_prefix(cidr) || cidr.contains_prefix(a));
                if !steerable {
                    continue;
                }
                // Covered = the local-route set tiles the whole prefix
                // (structural rules above guarantee each is inside it
                // or disjoint from it, and that they don't overlap).
                let (lp_start, lp_end) = range(cidr);
                let mut pieces: Vec<(u64, u64)> = local_routes
                    .iter()
                    .filter(|(p, _)| cidr.contains_prefix(p))
                    .map(|(p, _)| range(p))
                    .collect();
                pieces.sort_unstable();
                let mut cursor = lp_start;
                for (s, e) in pieces {
                    if s > cursor {
                        break;
                    }
                    cursor = cursor.max(e);
                }
                if cursor < lp_end {
                    return Err(ConfigError::parse(
                        *line,
                        format!(
                            "`port {dst_port}` steers direction dst but local prefix {}/{} \
                             (steerable via the allowlist) is not fully covered by \
                             vpp-offload `local-route` lines: inbound steered to an \
                             uncovered address would blackhole in VPP, which has no \
                             local delivery for it. Add `local-route {}/{} port <iface> \
                             vlan <vid>` (or steer that port `direction src`)",
                            cidr.addr, cidr.prefix_len, cidr.addr, cidr.prefix_len
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Same, but with a caller-provided sysfs root (for tests).
    pub fn validate_interfaces_in(&self, sysfs_net: &Path) -> Result<(), ConfigError> {
        for m in &self.modules {
            for d in &m.directives {
                let (iface, line) = match d {
                    ModuleDirective::Attach { iface, line, .. } => (iface, line),
                    ModuleDirective::LocalPrefix { iface, line, .. } => (iface, line),
                    ModuleDirective::LocalPrefix6 { iface, line, .. } => (iface, line),
                    ModuleDirective::FallbackDefault { iface, line, .. } => (iface, line),
                    ModuleDirective::GuardInterface { iface, line } => (iface, line),
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

    /// guard-section validation. Pure config logic — no sysfs — so it
    /// runs everywhere `parse` does (startup, feasibility, SIGHUP; the
    /// three call sites must stay in step or reload silently skips
    /// enforcement — see the loader's reload-validation note).
    ///
    /// Also enforces [`GUARD_MAX_INTERFACES`].
    ///
    /// Rules:
    /// - an empty `guard` section is refused (same reasoning as
    ///   vpp-offload: one verdict at the earliest point);
    /// - duplicate `interface` lines are refused;
    /// - a class rule naming an interface with no `interface` line is
    ///   refused (almost certainly a typo, and the rule would silently
    ///   never take effect);
    /// - duplicate `(class, interface)` pairs are refused;
    /// - an `interface` with zero class rules is refused (a policer
    ///   that polices nothing attaches and reports healthy — a silent
    ///   no-op, this repo's named enemy).
    pub fn validate_guard(&self) -> Result<(), ConfigError> {
        let Some(guard) = self.modules.iter().find(|m| m.name == "guard") else {
            return Ok(());
        };

        // (iface, first-declaration line) for `interface` lines.
        let mut ifaces: Vec<(&String, usize)> = Vec::new();
        for d in &guard.directives {
            if let ModuleDirective::GuardInterface { iface, line } = d {
                if let Some((_, prev)) = ifaces.iter().find(|(i, _)| *i == iface) {
                    return Err(ConfigError::Parse {
                        line: *line,
                        message: format!(
                            "module guard: duplicate `interface {iface}` (first declared \
                             on line {prev})"
                        ),
                    });
                }
                ifaces.push((iface, *line));
            }
        }
        // Specifically ≥1 `interface` line, not merely a non-empty
        // directive list: the directive namespace is shared across
        // module sections, so `module guard\n  attach eth0 native`
        // parses — and a raw-emptiness check would wave through a
        // section whose every directive belongs to another module,
        // attaching nothing while reporting healthy (review finding,
        // PR #204).
        if ifaces.is_empty() {
            return Err(ConfigError::Parse {
                line: 0,
                message: "module guard: section declares no `interface` lines; add \
                          `interface <iface>` and at least one class rule, or remove \
                          the section"
                    .to_string(),
            });
        }
        if ifaces.len() > GUARD_MAX_INTERFACES {
            // Refused here, before any filter is installed — failing
            // only at attach would leave the first 64 interfaces'
            // filters live behind a startup error (review finding,
            // PR #205).
            return Err(ConfigError::Parse {
                line: ifaces[GUARD_MAX_INTERFACES].1,
                message: format!(
                    "module guard: {} `interface` lines exceed the {GUARD_MAX_INTERFACES} \
                     the datapath's per-interface config map holds",
                    ifaces.len()
                ),
            });
        }

        // Class rules: (class-name, iface, line), checked for
        // undeclared interfaces and per-class duplicates.
        let mut rules: Vec<(&'static str, &String, usize)> = Vec::new();
        for d in &guard.directives {
            let (class, iface, line) = match d {
                ModuleDirective::GuardArpNsRatelimit { iface, line, .. } => {
                    ("arp-ns-ratelimit", iface, *line)
                }
                ModuleDirective::GuardBcastMcastRatelimit { iface, line, .. } => {
                    ("bcast-mcast-ratelimit", iface, *line)
                }
                ModuleDirective::GuardLldp { iface, line, .. } => ("lldp", iface, *line),
                ModuleDirective::GuardForeignSrc { iface, line, .. } => {
                    ("foreign-src", iface, *line)
                }
                _ => continue,
            };
            if !ifaces.iter().any(|(i, _)| *i == iface) {
                return Err(ConfigError::Parse {
                    line,
                    message: format!(
                        "module guard: `{class} {iface}` names an interface with no \
                         `interface {iface}` line; the rule would never take effect"
                    ),
                });
            }
            if let Some((_, _, prev)) = rules.iter().find(|(c, i, _)| *c == class && *i == iface) {
                return Err(ConfigError::Parse {
                    line,
                    message: format!(
                        "module guard: duplicate `{class}` for {iface} (first declared \
                         on line {prev})"
                    ),
                });
            }
            rules.push((class, iface, line));
        }

        for (iface, line) in &ifaces {
            if !rules.iter().any(|(_, i, _)| i == iface) {
                return Err(ConfigError::Parse {
                    line: *line,
                    message: format!(
                        "module guard: `interface {iface}` declares no rules; add at \
                         least one class rule for it or remove the line"
                    ),
                });
            }
        }

        // v1 rides the fast-path daemon (the vpp-offload precedent):
        // the startup feasibility gate's REQUIRED probes are the
        // fast-path module's (XDP, LPM/devmap, redirect helpers —
        // none of which a tc-egress policer needs), so a guard-only
        // config would be refused for capabilities it never uses,
        // several confusing steps downstream. Requiring the section
        // makes the limitation explicit at the earliest point;
        // deriving the probe set from the configured modules lifts it
        // later. Checked LAST so a malformed guard section reports
        // its own specific problem first.
        if !self.modules.iter().any(|m| m.name == "fast-path") {
            return Err(ConfigError::Parse {
                line: 0,
                message: "module guard: requires a `module fast-path` section (guard v1 \
                          runs alongside the fast-path daemon; the startup capability \
                          gate assumes it — a guard-only config cannot start)"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// neigh-snoop-section validation. Pure config logic — no sysfs —
    /// so it runs everywhere `parse` does (startup, feasibility,
    /// SIGHUP; the call sites must stay in step or reload silently
    /// applies a config startup would refuse).
    ///
    /// Deliberately **not** a sysfs existence check on `bridge` names:
    /// the platform daemon recreates bridges on provision and the
    /// module tracks them by name, so an absent bridge is a health
    /// row, not a startup refusal.
    ///
    /// Rules:
    /// - ≥1 `bridge` line (a section holding only another module's
    ///   directives parses; it must not load as an empty snooper);
    /// - no duplicate `bridge`; at most [`NEIGH_SNOOP_MAX_BRIDGES`];
    /// - `prefix` / `peer` naming an undeclared bridge is refused;
    /// - every `bridge` needs ≥1 `prefix` (an empty allowlist learns
    ///   nothing and reports healthy — a silent no-op);
    /// - duplicate `(bridge, cidr)` prefixes, duplicate `deny-mac`, and
    ///   a peer address appearing twice anywhere in the section are
    ///   refused;
    /// - a `peer` address outside every prefix of its bridge is
    ///   refused (it would be `never_heard` forever);
    /// - more peer addresses on a bridge than `table-max` is refused;
    /// - every singleton directive at most once;
    /// - `persist-dir` may not equal the global `state-dir` (the
    ///   per-bridge JSON files would share a directory with the
    ///   daemon's registry, health and pid files);
    /// - `route-server` peers require `frr-gate` (route-server
    ///   coverage is meaningless without the gate);
    /// - last, a `module fast-path` section is required (the ix-mode
    ///   probe suppression lives in fast-path's resolver and the
    ///   startup capability gate assumes fast-path — the guard
    ///   precedent).
    pub fn validate_neigh_snoop(&self) -> Result<(), ConfigError> {
        let Some(sec) = self.modules.iter().find(|m| m.name == "neigh-snoop") else {
            return Ok(());
        };
        let refuse = |line: usize, msg: String| ConfigError::Parse {
            line,
            message: format!("module neigh-snoop: {msg}"),
        };

        let mut bridges: Vec<(&String, usize)> = Vec::new();
        for d in &sec.directives {
            if let ModuleDirective::SnoopBridge { iface, line, .. } = d {
                if let Some((_, prev)) = bridges.iter().find(|(i, _)| *i == iface) {
                    return Err(refuse(
                        *line,
                        format!("duplicate `bridge {iface}` (first declared on line {prev})"),
                    ));
                }
                bridges.push((iface, *line));
            }
        }
        if bridges.is_empty() {
            return Err(refuse(
                0,
                "section declares no `bridge` lines; add `bridge <iface>` and at least \
                 one `prefix` for it, or remove the section"
                    .to_string(),
            ));
        }
        if bridges.len() > NEIGH_SNOOP_MAX_BRIDGES {
            return Err(refuse(
                bridges[NEIGH_SNOOP_MAX_BRIDGES].1,
                format!(
                    "{} `bridge` lines exceed the {NEIGH_SNOOP_MAX_BRIDGES} the module \
                     supports",
                    bridges.len()
                ),
            ));
        }
        let declared = |iface: &String| bridges.iter().any(|(i, _)| *i == iface);

        let mut prefixes: Vec<(&String, ipnet::IpNet, usize)> = Vec::new();
        let mut deny_macs: Vec<([u8; 6], usize)> = Vec::new();
        let mut peer_addrs: Vec<(IpAddr, usize)> = Vec::new();
        let mut peer_count_by_bridge: Vec<(&String, usize)> = Vec::new();
        let mut any_route_server = false;
        let mut singletons: Vec<(&'static str, usize)> = Vec::new();
        let mut table_max = NEIGH_SNOOP_DEFAULT_TABLE_MAX;
        let mut persist_dir: Option<(&PathBuf, usize)> = None;
        let mut has_gate = false;

        let mut singleton = |name: &'static str, line: usize| -> Result<(), ConfigError> {
            if let Some((_, prev)) = singletons.iter().find(|(n, _)| *n == name) {
                return Err(refuse(
                    line,
                    format!("`{name}` may appear once (first on line {prev})"),
                ));
            }
            singletons.push((name, line));
            Ok(())
        };

        for d in &sec.directives {
            match d {
                ModuleDirective::SnoopPrefix { iface, cidr, line } => {
                    if !declared(iface) {
                        return Err(refuse(
                            *line,
                            format!(
                                "`prefix {iface} {cidr}` names a bridge with no `bridge {iface}` \
                                 line; it would never take effect"
                            ),
                        ));
                    }
                    if let Some((_, _, prev)) =
                        prefixes.iter().find(|(i, c, _)| *i == iface && c == cidr)
                    {
                        return Err(refuse(
                            *line,
                            format!("duplicate `prefix {iface} {cidr}` (first on line {prev})"),
                        ));
                    }
                    prefixes.push((iface, *cidr, *line));
                }
                ModuleDirective::SnoopDenyMac { mac, line } => {
                    if let Some((_, prev)) = deny_macs.iter().find(|(m, _)| m == mac) {
                        return Err(refuse(
                            *line,
                            format!(
                                "duplicate `deny-mac {}` (first on line {prev})",
                                format_mac(*mac)
                            ),
                        ));
                    }
                    deny_macs.push((*mac, *line));
                }
                ModuleDirective::SnoopPeer {
                    iface,
                    addrs,
                    route_server,
                    line,
                } => {
                    if !declared(iface) {
                        return Err(refuse(
                            *line,
                            format!(
                                "`peer {iface} ...` names a bridge with no `bridge {iface}` \
                                 line; it would never take effect"
                            ),
                        ));
                    }
                    for a in addrs {
                        if let Some((_, prev)) = peer_addrs.iter().find(|(p, _)| p == a) {
                            return Err(refuse(
                                *line,
                                format!(
                                    "peer address {a} appears twice (first on line {prev}); one \
                                     router, one `peer` line"
                                ),
                            ));
                        }
                        peer_addrs.push((*a, *line));
                    }
                    match peer_count_by_bridge.iter_mut().find(|(i, _)| *i == iface) {
                        Some((_, n)) => *n += addrs.len(),
                        None => peer_count_by_bridge.push((iface, addrs.len())),
                    }
                    any_route_server |= *route_server;
                }
                ModuleDirective::SnoopPersistDir { path, line } => {
                    singleton("persist-dir", *line)?;
                    persist_dir = Some((path, *line));
                }
                ModuleDirective::SnoopSeedMaxAge { line, .. } => singleton("seed-max-age", *line)?,
                ModuleDirective::SnoopInstallRate { line, .. } => singleton("install-rate", *line)?,
                ModuleDirective::SnoopTableMax { max, line } => {
                    singleton("table-max", *line)?;
                    table_max = *max;
                }
                ModuleDirective::SnoopCoverageInterval { line, .. } => {
                    singleton("coverage-interval", *line)?
                }
                ModuleDirective::SnoopFrrGate { line, .. } => {
                    singleton("frr-gate", *line)?;
                    has_gate = true;
                }
                ModuleDirective::SnoopRsCoverageInterval { line, .. } => {
                    singleton("rs-coverage-interval", *line)?
                }
                _ => {}
            }
        }

        for (iface, line) in &bridges {
            if !prefixes.iter().any(|(i, _, _)| i == iface) {
                return Err(refuse(
                    *line,
                    format!(
                        "`bridge {iface}` has no `prefix` lines; an empty allowlist learns \
                         nothing — add `prefix {iface} <cidr>` or remove the bridge"
                    ),
                ));
            }
        }
        for d in &sec.directives {
            if let ModuleDirective::SnoopPeer {
                iface, addrs, line, ..
            } = d
            {
                for a in addrs {
                    let covered = prefixes
                        .iter()
                        .any(|(i, c, _)| *i == iface && c.contains(a));
                    if !covered {
                        return Err(refuse(
                            *line,
                            format!(
                                "peer {a} is outside every `prefix` of {iface}; it could never \
                                 be learned"
                            ),
                        ));
                    }
                }
            }
        }
        for (iface, n) in &peer_count_by_bridge {
            if *n > table_max as usize {
                return Err(refuse(
                    0,
                    format!(
                        "{n} peer addresses on {iface} exceed `table-max {table_max}`; the \
                         table could not hold them all"
                    ),
                ));
            }
        }
        if let Some((path, line)) = persist_dir {
            if *path == self.global.state_dir {
                return Err(refuse(
                    line,
                    format!(
                        "`persist-dir {}` is the global state-dir; use a subdirectory (the \
                         default is <state-dir>/{NEIGH_SNOOP_PERSIST_SUBDIR})",
                        path.display()
                    ),
                ));
            }
        }
        if any_route_server && !has_gate {
            return Err(refuse(
                0,
                "`peer ... route-server` requires `frr-gate`; route-server coverage is \
                 meaningless without the next-hop gate"
                    .to_string(),
            ));
        }
        // Checked LAST so a malformed section reports its own problem
        // first (the guard precedent, same rationale).
        if !self.modules.iter().any(|m| m.name == "fast-path") {
            return Err(refuse(
                0,
                "requires a `module fast-path` section (the ix-mode probe suppression \
                 lives in fast-path's neighbour resolver and the startup capability gate \
                 assumes fast-path — a neigh-snoop-only config cannot start)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// `aa:bb:cc:dd:ee:ff` rendering shared by error messages and the
/// module crate's persistence layer.
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse a `xx:xx:xx:xx:xx:xx` hardware address. Refuses anything but
/// six colon-separated hex octets. Does **not** judge the value (zero,
/// group bit); callers that need that check it.
pub fn parse_mac_literal(tok: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = tok.split(':').collect();
    if parts.len() != 6 {
        return Err(format!(
            "`{tok}` is not a MAC address (expected six colon-separated hex octets)"
        ));
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return Err(format!(
                "`{tok}`: octet `{p}` must be exactly two hex digits"
            ));
        }
        mac[i] =
            u8::from_str_radix(p, 16).map_err(|_| format!("`{tok}`: octet `{p}` is not hex"))?;
    }
    Ok(mac)
}

/// One warning per `local-prefix` / `local-prefix6` directive that no
/// same-family `allow-prefix` / `allow-prefix6` even overlaps.
///
/// The allowlist is consulted *before* the FIB lookup, so a synthesized
/// host route does nothing when inbound traffic to it never matches the
/// allowlist — the feature silently no-ops. The runbook names this the
/// top operator footgun, and `local-prefix6` doubles the exposure
/// because the v4 and v6 allowlists are declared separately.
///
/// Advisory only, never fatal: the check looks for *any overlap* rather
/// than full coverage, so it fires only on the forgot-it-entirely case
/// and cannot false-positive on a prefix jointly covered by several
/// narrower allow entries. Callers log each returned string at WARN.
pub fn uncovered_local_prefix_warnings(directives: &[ModuleDirective]) -> Vec<String> {
    let mut allow_v4: Vec<Ipv4Prefix> = Vec::new();
    let mut allow_v6: Vec<Ipv6Prefix> = Vec::new();
    for d in directives {
        match d {
            ModuleDirective::AllowPrefix4(p) => allow_v4.push(*p),
            ModuleDirective::AllowPrefix6(p) => allow_v6.push(*p),
            _ => {}
        }
    }
    let overlaps_v4 = |l: &Ipv4Prefix| {
        allow_v4
            .iter()
            .any(|a| a.contains_prefix(l) || l.contains_prefix(a))
    };
    let overlaps_v6 = |l: &Ipv6Prefix| {
        allow_v6
            .iter()
            .any(|a| a.contains_prefix(l) || l.contains_prefix(a))
    };

    let mut out = Vec::new();
    for d in directives {
        match d {
            ModuleDirective::LocalPrefix {
                cidr, iface, line, ..
            } if !overlaps_v4(cidr) => {
                out.push(format!(
                    "local-prefix {}/{} via {iface} (line {line}) has no overlapping \
                     allow-prefix; the allowlist is checked before the FIB lookup, so its \
                     synthesized /32s will never be used. Add a covering `allow-prefix`",
                    cidr.addr, cidr.prefix_len
                ));
            }
            ModuleDirective::LocalPrefix6 { cidr, iface, line } if !overlaps_v6(cidr) => {
                out.push(format!(
                    "local-prefix6 {}/{} via {iface} (line {line}) has no overlapping \
                     allow-prefix6; the allowlist is checked before the FIB lookup, so its \
                     synthesized /128s will never be used. Add a covering `allow-prefix6` \
                     (the v4 allowlist does not cover v6)",
                    cidr.addr, cidr.prefix_len
                ));
            }
            _ => {}
        }
    }
    out
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
                    // The controller spawns at most one route source
                    // and every consumer selects "the first" — a
                    // second directive could silently diverge from
                    // the first (the anyip preflight vs the
                    // controller's selection, review finding on
                    // PR #196). The runbook has always said "exactly
                    // one route-source"; now the parser does too.
                    if matches!(d, ModuleDirective::RouteSource(_))
                        && modules[i]
                            .directives
                            .iter()
                            .any(|e| matches!(e, ModuleDirective::RouteSource(_)))
                    {
                        return Err(ConfigError::parse(
                            line,
                            "duplicate `route-source` in one module section; exactly one \
                             feed is supported per module",
                        ));
                    }
                    // One attach-time write per interface: two lines
                    // would merge over each other in file order, and
                    // "which value is on the NIC" should not depend on
                    // reading the config bottom-up.
                    if matches!(d, ModuleDirective::Coalesce { .. }) {
                        if let Some(prev) = modules[i].directives.iter().find_map(|e| match e {
                            ModuleDirective::Coalesce { line, .. } => Some(*line),
                            _ => None,
                        }) {
                            return Err(ConfigError::parse(
                                line,
                                format!(
                                    "duplicate `coalesce` (first on line {prev}); put every \
                                     parameter on one line"
                                ),
                            ));
                        }
                    }
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
                ConfigError::parse(line, "local-prefix requires a CIDR (e.g. 192.0.2.0/24)")
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
            let p: Ipv4Prefix = cidr_tok.parse().map_err(|e: String| {
                ConfigError::parse(line, wrong_family_hint(e, cidr_tok, "local-prefix"))
            })?;
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
        "local-prefix6" => {
            // Grammar: local-prefix6 <cidr> via <iface>
            //
            // Structure mirrors the `local-prefix` arm above, including
            // the ordering: `via`/iface/tail-flag errors are reported
            // before the CIDR is parsed. There are no valid tail flags
            // here, so the tail loop only rejects.
            let cidr_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "local-prefix6 requires a CIDR (e.g. 2001:db8:0:1337::/64)",
                )
            })?;
            let via_tok = rest.next().ok_or_else(|| {
                ConfigError::parse(line, "local-prefix6 requires `via <iface>` after the CIDR")
            })?;
            if via_tok != "via" {
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "local-prefix6: expected `via` after the CIDR, got `{via_tok}` \
                         (form: `local-prefix6 <cidr> via <iface>`)"
                    ),
                ));
            }
            let iface = rest.next().ok_or_else(|| {
                ConfigError::parse(
                    line,
                    "local-prefix6: expected an interface name after `via`",
                )
            })?;
            validate_iface_name(line, "local-prefix6", iface)?;
            // No valid tail flags in this grammar, so the first extra
            // token is always an error. `arp-scavenge` gets a specific
            // message because reaching for it here is the natural
            // mistake once an operator knows the v4 form.
            if let Some(tail) = rest.next() {
                if tail == "arp-scavenge" {
                    return Err(ConfigError::parse(
                        line,
                        "local-prefix6: arp-scavenge is IPv4-only. A /64 is not enumerable, \
                         and SLAAC / RFC 7217 scatter host addresses across the whole \
                         64-bit interface identifier, so a swept range would find almost \
                         nothing. IPv6 relies on reactive seeding instead (startup \
                         neighbour dump + RTM_NEWNEIGH), which already covers every host \
                         the kernel has resolved",
                    ));
                }
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "local-prefix6: unknown tail flag `{tail}` \
                         (form: `local-prefix6 <cidr> via <iface>`; no flags are recognized)"
                    ),
                ));
            }
            let p: Ipv6Prefix = cidr_tok.parse().map_err(|e: String| {
                ConfigError::parse(line, wrong_family_hint(e, cidr_tok, "local-prefix6"))
            })?;
            reject_non_harvestable_prefix(line, &p)?;
            Ok(ModuleDirective::LocalPrefix6 {
                cidr: p,
                iface: iface.to_string(),
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
        "fib-cache" => {
            let v = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "fib-cache requires on|off"))?;
            if rest.next().is_some() {
                return Err(ConfigError::parse(line, "fib-cache takes one argument"));
            }
            let on = match v {
                "on" => true,
                "off" => false,
                other => {
                    return Err(ConfigError::parse(
                        line,
                        format!("fib-cache expects on|off, got `{other}`"),
                    ))
                }
            };
            Ok(ModuleDirective::FibCache(on))
        }
        "coalesce" => parse_coalesce(line, rest),
        "bridge-resolve" => parse_single_arg(line, rest, "bridge-resolve", |t| {
            let v: ToggleAutoOnOff = t.parse().map_err(|e: String| e)?;
            Ok(ModuleDirective::BridgeResolve(v))
        }),
        "fdb-pin" => parse_single_arg(line, rest, "fdb-pin", |t| {
            let v: ToggleAutoOnOff = t.parse().map_err(|e: String| e)?;
            Ok(ModuleDirective::FdbPin(v))
        }),
        // --- vpp-offload directives (phase 4) ---
        "port" => {
            // port <iface> cores <n> steer on|off [vlans <id>[,<id>...]]
            let iface = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, "port requires an interface"))?;
            validate_iface_name(line, "port", iface)?;
            let usage = "port takes: <iface> cores <n> steer on|off [vlans <id>[,<id>...]|all] \
                         [direction src|dst|both]";
            if rest.next() != Some("cores") {
                return Err(ConfigError::parse(line, usage));
            }
            // 0 is legal: the port gets no worker of its own; its one
            // rx queue is polled by a worker shared with other ports
            // (`vpp_worker_count`). Whether such a port
            // may steer is a cross-directive rule, checked in
            // `validate_vpp_offload`.
            let cores: u16 = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, usage))?
                .parse()
                .map_err(|_| ConfigError::parse(line, "cores must be a non-negative integer"))?;
            if rest.next() != Some("steer") {
                return Err(ConfigError::parse(line, usage));
            }
            let steer = match rest.next() {
                Some("on") => true,
                Some("off") => false,
                _ => return Err(ConfigError::parse(line, "steer expects on|off")),
            };
            let mut vlans: Vec<u16> = Vec::new();
            let mut vlans_all = false;
            let mut direction: Option<VppSteerDirection> = None;
            let mut tail = rest.next();
            if tail == Some("vlans") {
                let csv = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "vlans requires a comma-separated id list or `all`")
                })?;
                // `all`: follow whatever tagged VLANs the kernel bridge
                // carries on this port, now and as they are added.
                if csv == "all" {
                    vlans_all = true;
                }
                for tok in csv.split(',').filter(|_| !vlans_all) {
                    let vid: u16 = tok.parse().map_err(|_| {
                        ConfigError::parse(line, "vlans ids must be integers 1-4094")
                    })?;
                    // 0 is priority-tagged, 4095 reserved; neither
                    // names a subinterface anything can classify to.
                    if !(1..=4094).contains(&vid) {
                        return Err(ConfigError::parse(line, "vlans ids must be 1-4094"));
                    }
                    if vlans.contains(&vid) {
                        return Err(ConfigError::parse(line, "duplicate vlan id"));
                    }
                    vlans.push(vid);
                }
                tail = rest.next();
            }
            if tail == Some("direction") {
                let tok = rest
                    .next()
                    .ok_or_else(|| ConfigError::parse(line, "direction expects src|dst|both"))?;
                let d: VppSteerDirection = tok
                    .parse()
                    .map_err(|e: String| ConfigError::parse(line, e))?;
                direction = Some(d);
                tail = rest.next();
            }
            if tail.is_some() {
                return Err(ConfigError::parse(line, usage));
            }
            Ok(ModuleDirective::VppPort {
                iface: iface.to_string(),
                cores,
                steer,
                vlans,
                vlans_all,
                direction,
                line,
            })
        }
        "vpp-binary" => parse_single_arg(line, rest, "vpp-binary", |t| {
            Ok(ModuleDirective::VppBinary(t.to_string()))
        }),
        "expected-routes" => parse_single_arg(line, rest, "expected-routes", |t| {
            let n: u64 = t
                .parse()
                .map_err(|_| "expected-routes must be a positive integer".to_string())?;
            if n == 0 {
                return Err("expected-routes must be >= 1".to_string());
            }
            Ok(ModuleDirective::ExpectedRoutes(n))
        }),
        "loopback-address" => parse_single_arg(line, rest, "loopback-address", |t| {
            let p: Ipv4Prefix = t
                .parse()
                .map_err(|e: String| format!("loopback-address: {e}"))?;
            Ok(ModuleDirective::VppLoopbackAddress(p))
        }),
        "local-route" => {
            // local-route <v4-cidr> port <iface> vlan <vid>
            let usage = "local-route takes: <v4-cidr> port <iface> vlan <vid>";
            let cidr_tok = rest.next().ok_or_else(|| ConfigError::parse(line, usage))?;
            if rest.next() != Some("port") {
                return Err(ConfigError::parse(line, usage));
            }
            let iface = rest.next().ok_or_else(|| ConfigError::parse(line, usage))?;
            validate_iface_name(line, "local-route", iface)?;
            if rest.next() != Some("vlan") {
                return Err(ConfigError::parse(line, usage));
            }
            let vid: u16 = rest
                .next()
                .ok_or_else(|| ConfigError::parse(line, usage))?
                .parse()
                .map_err(|_| ConfigError::parse(line, "vlan id must be an integer 1-4094"))?;
            if !(1..=4094).contains(&vid) {
                return Err(ConfigError::parse(line, "vlan id must be 1-4094"));
            }
            if rest.next().is_some() {
                return Err(ConfigError::parse(line, usage));
            }
            let prefix: Ipv4Prefix = cidr_tok
                .parse()
                .map_err(|e: String| ConfigError::parse(line, format!("local-route: {e}")))?;
            Ok(ModuleDirective::VppLocalRoute {
                prefix,
                iface: iface.to_string(),
                vlan: vid,
                line,
            })
        }
        "steer-exempt" => parse_single_arg(line, rest, "steer-exempt", |t| {
            let p: Ipv4Prefix = t
                .parse()
                .map_err(|e: String| format!("steer-exempt: {e}"))?;
            Ok(ModuleDirective::VppSteerExempt(p))
        }),
        "require-table-complete" => {
            parse_single_arg(line, rest, "require-table-complete", |t| match t {
                "on" => Ok(ModuleDirective::VppRequireTableComplete(true)),
                "off" => Ok(ModuleDirective::VppRequireTableComplete(false)),
                _ => Err("require-table-complete expects on|off".to_string()),
            })
        }
        "steer-direction" => parse_single_arg(line, rest, "steer-direction", |t| {
            let d: VppSteerDirection = t.parse()?;
            Ok(ModuleDirective::VppSteerDirection(d))
        }),
        "hugepages" => parse_single_arg(line, rest, "hugepages", |t| {
            let n: u32 = t
                .parse()
                .map_err(|_| "hugepages must be a positive integer".to_string())?;
            if n == 0 {
                return Err("hugepages must be >= 1".to_string());
            }
            Ok(ModuleDirective::VppHugepages(n))
        }),
        "steer-capacity" => parse_single_arg(line, rest, "steer-capacity", |t| {
            let n: u16 = t.parse().map_err(|_| {
                format!("steer-capacity must be an integer 1-{VPP_MAX_STEER_CAPACITY}")
            })?;
            if !(1..=VPP_MAX_STEER_CAPACITY).contains(&n) {
                return Err(format!("steer-capacity must be 1-{VPP_MAX_STEER_CAPACITY}"));
            }
            Ok(ModuleDirective::VppSteerCapacity(n))
        }),
        "driver-workaround" => parse_driver_workaround(line, rest),
        "forwarding-mode" => parse_single_arg(line, rest, "forwarding-mode", |t| {
            let mode: ForwardingMode = t.parse().map_err(|e: String| e)?;
            Ok(ModuleDirective::ForwardingMode(mode))
        }),
        "route-source" => parse_route_source(line, rest),
        "integrity-authority" => parse_integrity_authority(line, rest),
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
        "interface" => parse_single_arg(line, rest, "interface", |t| {
            validate_iface_name(line, "interface", t).map_err(|e| e.to_string())?;
            Ok(ModuleDirective::GuardInterface {
                iface: t.to_string(),
                line,
            })
        }),
        "arp-ns-ratelimit" => {
            parse_guard_ratelimit(line, rest, "arp-ns-ratelimit", ARP_NS_RATELIMIT_USAGE)
        }
        "bcast-mcast-ratelimit" => parse_guard_ratelimit(
            line,
            rest,
            "bcast-mcast-ratelimit",
            BCAST_MCAST_RATELIMIT_USAGE,
        ),
        "lldp" => parse_guard_action(line, rest, "lldp"),
        "foreign-src" => parse_guard_action(line, rest, "foreign-src"),
        "bridge" => parse_snoop_bridge(line, rest),
        "prefix" => parse_snoop_prefix(line, rest),
        "deny-mac" => parse_single_arg(line, rest, "deny-mac", |t| {
            let mac = parse_mac_literal(t)?;
            if mac == [0u8; 6] {
                return Err("the all-zero address is not a hardware address".to_string());
            }
            if mac[0] & 1 != 0 {
                return Err(format!(
                    "`{t}` has the group bit set (multicast/broadcast); ARP/ND senders are \
                     unicast, so this could never match"
                ));
            }
            Ok(ModuleDirective::SnoopDenyMac { mac, line })
        }),
        "peer" => parse_snoop_peer(line, rest),
        "persist-dir" => parse_single_arg(line, rest, "persist-dir", |t| {
            let path = validate_safe_path(line, "persist-dir", t).map_err(|e| e.to_string())?;
            Ok(ModuleDirective::SnoopPersistDir { path, line })
        }),
        "seed-max-age" => parse_single_arg(line, rest, "seed-max-age", |t| {
            let max_age = parse_days(t, 1, 365)?;
            Ok(ModuleDirective::SnoopSeedMaxAge { max_age, line })
        }),
        "install-rate" => parse_snoop_rate(line, rest),
        "table-max" => parse_single_arg(line, rest, "table-max", |t| {
            let max: u32 = t.parse().map_err(|e| format!("bad integer `{t}`: {e}"))?;
            if !(SNOOP_TABLE_MAX_RANGE.0..=SNOOP_TABLE_MAX_RANGE.1).contains(&max) {
                return Err(format!(
                    "table-max must be between {} and {}",
                    SNOOP_TABLE_MAX_RANGE.0, SNOOP_TABLE_MAX_RANGE.1
                ));
            }
            Ok(ModuleDirective::SnoopTableMax { max, line })
        }),
        "coverage-interval" => parse_single_arg(line, rest, "coverage-interval", |t| {
            let interval = parse_bounded_secs(line, t, "coverage-interval", 5, 3600)?;
            Ok(ModuleDirective::SnoopCoverageInterval { interval, line })
        }),
        "frr-gate" => parse_snoop_frr_gate(line, rest),
        "rs-coverage-interval" => parse_single_arg(line, rest, "rs-coverage-interval", |t| {
            let interval = parse_bounded_secs(line, t, "rs-coverage-interval", 5, 3600)?;
            Ok(ModuleDirective::SnoopRsCoverageInterval { interval, line })
        }),
        other => Err(ConfigError::parse(
            line,
            format!("unknown directive `{other}` in module section"),
        )),
    }
}

const ARP_NS_RATELIMIT_USAGE: &str =
    "arp-ns-ratelimit takes: <iface> rate <n>/<dur> [burst <m>] [monitor]";
const BCAST_MCAST_RATELIMIT_USAGE: &str =
    "bcast-mcast-ratelimit takes: <iface> rate <n>/<dur> [burst <m>] [monitor]";

/// Longest token-bucket interval the guard accepts. The BPF side
/// stores GCRA deadlines in nanoseconds; bounding the interval (and
/// burst, below) keeps `(burst - 1) * (per / rate)` far from u64
/// overflow without runtime checks in the datapath.
const GUARD_RATELIMIT_MAX_PER: Duration = Duration::from_secs(3600);
const GUARD_RATELIMIT_MAX_BURST: u32 = 65_535;

/// Shared tail parser for the two guard ratelimit directives:
/// `<iface> rate <n>/<dur> [burst <m>] [monitor]`.
fn parse_guard_ratelimit<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
    directive: &'static str,
    usage: &'static str,
) -> Result<ModuleDirective, ConfigError> {
    let iface = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, format!("{directive} requires an interface")))?;
    validate_iface_name(line, directive, iface)?;
    if rest.next() != Some("rate") {
        return Err(ConfigError::parse(line, usage));
    }
    let rate_tok = rest.next().ok_or_else(|| ConfigError::parse(line, usage))?;
    let (n_tok, dur_tok) = rate_tok.split_once('/').ok_or_else(|| {
        ConfigError::parse(
            line,
            format!("{directive}: rate must be <n>/<dur> (e.g. 3/60s), got `{rate_tok}`"),
        )
    })?;
    let rate: u32 = n_tok.parse().map_err(|_| {
        ConfigError::parse(line, format!("{directive}: rate count must be an integer"))
    })?;
    if rate == 0 {
        return Err(ConfigError::parse(
            line,
            format!("{directive}: rate count must be >= 1"),
        ));
    }
    let per = parse_duration(line, dur_tok, directive)?;
    if per.is_zero() {
        return Err(ConfigError::parse(
            line,
            format!("{directive}: rate interval must be non-zero"),
        ));
    }
    if per > GUARD_RATELIMIT_MAX_PER {
        return Err(ConfigError::parse(
            line,
            format!("{directive}: rate interval must be 3600s or less"),
        ));
    }
    // The per-token interval is per/rate; refuse sub-microsecond
    // emission intervals — they are configuration mistakes (a limiter
    // admitting >1M frames/s per target limits nothing) and they are
    // where integer ns math stops being meaningfully accurate.
    if per.as_nanos() / u128::from(rate) < 1_000 {
        return Err(ConfigError::parse(
            line,
            format!("{directive}: rate exceeds 1 frame per microsecond per target"),
        ));
    }
    let mut burst = rate;
    let mut monitor = false;
    let mut tail = rest.next();
    if tail == Some("burst") {
        let b_tok = rest.next().ok_or_else(|| ConfigError::parse(line, usage))?;
        burst = b_tok.parse().map_err(|_| {
            ConfigError::parse(line, format!("{directive}: burst must be an integer"))
        })?;
        if burst == 0 {
            return Err(ConfigError::parse(
                line,
                format!("{directive}: burst must be >= 1"),
            ));
        }
        if burst > GUARD_RATELIMIT_MAX_BURST {
            return Err(ConfigError::parse(
                line,
                format!("{directive}: burst must be {GUARD_RATELIMIT_MAX_BURST} or less"),
            ));
        }
        tail = rest.next();
    }
    if tail == Some("monitor") {
        monitor = true;
        tail = rest.next();
    }
    if tail.is_some() {
        return Err(ConfigError::parse(line, usage));
    }
    let mk = |iface: String| match directive {
        "arp-ns-ratelimit" => ModuleDirective::GuardArpNsRatelimit {
            iface,
            rate,
            per,
            burst,
            monitor,
            line,
        },
        _ => ModuleDirective::GuardBcastMcastRatelimit {
            iface,
            rate,
            per,
            burst,
            monitor,
            line,
        },
    };
    Ok(mk(iface.to_string()))
}

/// Shared parser for the two action-only guard directives:
/// `<iface> drop|monitor`. The action is mandatory — a default here
/// would make `lldp br3998` silently enforce or silently observe, and
/// either surprise is worse than one more token.
fn parse_guard_action<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
    directive: &'static str,
) -> Result<ModuleDirective, ConfigError> {
    let usage = format!("{directive} takes: <iface> drop|monitor");
    let iface = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, usage.clone()))?;
    validate_iface_name(line, directive, iface)?;
    let monitor = match rest.next() {
        Some("drop") => false,
        Some("monitor") => true,
        _ => return Err(ConfigError::parse(line, usage.clone())),
    };
    if rest.next().is_some() {
        return Err(ConfigError::parse(line, usage));
    }
    let iface = iface.to_string();
    Ok(match directive {
        "lldp" => ModuleDirective::GuardLldp {
            iface,
            monitor,
            line,
        },
        _ => ModuleDirective::GuardForeignSrc {
            iface,
            monitor,
            line,
        },
    })
}

// --- neigh-snoop grammar --------------------------------------------------

/// Inclusive bounds for `table-max`.
const SNOOP_TABLE_MAX_RANGE: (u32, u32) = (16, 1_048_576);
/// `install-rate` may not exceed this many writes per second: above it
/// the "limit" is a netlink storm, not pacing.
const SNOOP_INSTALL_RATE_MAX_PER_SEC: u128 = 1000;
const SNOOP_GATE_LIST_NAME_MAX: usize = 63;

/// `bridge <iface> [ix-mode]`.
fn parse_snoop_bridge<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    const USAGE: &str = "bridge takes: <iface> [ix-mode]";
    let iface = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, "bridge requires an interface"))?;
    validate_iface_name(line, "bridge", iface)?;
    let ix_mode = match rest.next() {
        None => false,
        Some("ix-mode") => true,
        Some(_) => return Err(ConfigError::parse(line, USAGE)),
    };
    if rest.next().is_some() {
        return Err(ConfigError::parse(line, USAGE));
    }
    Ok(ModuleDirective::SnoopBridge {
        iface: iface.to_string(),
        ix_mode,
        line,
    })
}

/// `prefix <iface> <cidr>`. Host bits are tolerated and cleared (the
/// `allow-prefix` convention); `/0` is refused because the allowlist
/// is the safety boundary and a `/0` learns everything.
fn parse_snoop_prefix<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    const USAGE: &str = "prefix takes: <iface> <cidr>";
    let iface = rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?;
    validate_iface_name(line, "prefix", iface)?;
    let cidr_tok = rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?;
    if rest.next().is_some() {
        return Err(ConfigError::parse(line, USAGE));
    }
    let cidr: ipnet::IpNet = cidr_tok
        .parse()
        .map_err(|e| ConfigError::parse(line, format!("prefix: bad CIDR `{cidr_tok}`: {e}")))?;
    if cidr.prefix_len() == 0 {
        return Err(ConfigError::parse(
            line,
            format!(
                "prefix: `{cidr_tok}` is a /0; the allowlist is the safety boundary and a /0 \
                 learns everything"
            ),
        ));
    }
    Ok(ModuleDirective::SnoopPrefix {
        iface: iface.to_string(),
        cidr: cidr.trunc(),
        line,
    })
}

/// `peer <iface> <ip> [<ip>...] [route-server]`.
fn parse_snoop_peer<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    const USAGE: &str = "peer takes: <iface> <ip> [<ip>...] [route-server]";
    let iface = rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?;
    validate_iface_name(line, "peer", iface)?;
    let mut addrs: Vec<IpAddr> = Vec::new();
    let mut route_server = false;
    for tok in rest {
        if tok == "route-server" {
            if route_server {
                return Err(ConfigError::parse(line, USAGE));
            }
            route_server = true;
            continue;
        }
        if route_server {
            // Addresses after the flag: almost certainly a typo.
            return Err(ConfigError::parse(line, USAGE));
        }
        let ip: IpAddr = tok
            .parse()
            .map_err(|_| ConfigError::parse(line, format!("peer: `{tok}` is not an IP address")))?;
        if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
            return Err(ConfigError::parse(
                line,
                format!("peer: `{tok}` cannot be a neighbour (unspecified, multicast or loopback)"),
            ));
        }
        if addrs.contains(&ip) {
            return Err(ConfigError::parse(
                line,
                format!("peer: `{tok}` listed twice on one line"),
            ));
        }
        addrs.push(ip);
    }
    if addrs.is_empty() {
        return Err(ConfigError::parse(line, USAGE));
    }
    Ok(ModuleDirective::SnoopPeer {
        iface: iface.to_string(),
        addrs,
        route_server,
        line,
    })
}

/// `install-rate <n>/<dur>`: the guard's rate token shape without the
/// `rate` keyword, burst or monitor.
fn parse_snoop_rate<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    const USAGE: &str = "install-rate takes: <n>/<dur> (e.g. 50/1s)";
    let tok = rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?;
    if rest.next().is_some() {
        return Err(ConfigError::parse(line, USAGE));
    }
    let (n_tok, dur_tok) = tok
        .split_once('/')
        .ok_or_else(|| ConfigError::parse(line, USAGE))?;
    let rate: u32 = n_tok
        .parse()
        .map_err(|_| ConfigError::parse(line, "install-rate: count must be an integer"))?;
    if rate == 0 {
        return Err(ConfigError::parse(line, "install-rate: count must be >= 1"));
    }
    let per = parse_duration(line, dur_tok, "install-rate")?;
    if per.is_zero() {
        return Err(ConfigError::parse(
            line,
            "install-rate: interval must be non-zero",
        ));
    }
    if per > Duration::from_secs(3600) {
        return Err(ConfigError::parse(
            line,
            "install-rate: interval must be 3600s or less",
        ));
    }
    // n / per ≤ 1000/s  ⇔  n * 1s ≤ 1000 * per
    if u128::from(rate) * 1_000_000_000 > SNOOP_INSTALL_RATE_MAX_PER_SEC * per.as_nanos() {
        return Err(ConfigError::parse(
            line,
            format!(
                "install-rate: more than {SNOOP_INSTALL_RATE_MAX_PER_SEC} neighbour writes per \
                 second is a netlink storm, not a rate limit"
            ),
        ));
    }
    Ok(ModuleDirective::SnoopInstallRate { rate, per, line })
}

/// `frr-gate v4 <list> v6 <list> [interval <N>s] [remove-after <N>s]`.
fn parse_snoop_frr_gate<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    const USAGE: &str = "frr-gate takes: v4 <list> v6 <list> [interval <N>s] [remove-after <N>s]";
    let list_name = |tok: &str| -> Result<String, ConfigError> {
        let ok = !tok.is_empty()
            && tok.len() <= SNOOP_GATE_LIST_NAME_MAX
            && tok
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !ok {
            return Err(ConfigError::parse(
                line,
                format!(
                    "frr-gate: `{tok}` is not a prefix-list name (letters, digits, `_`, `-`; \
                     at most {SNOOP_GATE_LIST_NAME_MAX} characters)"
                ),
            ));
        }
        Ok(tok.to_string())
    };
    expect_token(&mut rest, line, "v4")?;
    let v4_list = list_name(rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?)?;
    expect_token(&mut rest, line, "v6")?;
    let v6_list = list_name(rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?)?;
    if v4_list == v6_list {
        return Err(ConfigError::parse(
            line,
            "frr-gate: the v4 and v6 lists must have different names",
        ));
    }
    let mut interval = NEIGH_SNOOP_DEFAULT_GATE_INTERVAL;
    let mut remove_after = NEIGH_SNOOP_DEFAULT_GATE_REMOVE_AFTER;
    let mut seen_interval = false;
    let mut seen_remove = false;
    while let Some(tok) = rest.next() {
        let val = rest.next().ok_or_else(|| ConfigError::parse(line, USAGE))?;
        match tok {
            "interval" if !seen_interval => {
                interval = parse_bounded_secs(line, val, "frr-gate interval", 5, 600)
                    .map_err(|e| ConfigError::parse(line, e))?;
                seen_interval = true;
            }
            "remove-after" if !seen_remove => {
                remove_after = parse_bounded_secs(line, val, "frr-gate remove-after", 0, 3600)
                    .map_err(|e| ConfigError::parse(line, e))?;
                seen_remove = true;
            }
            _ => return Err(ConfigError::parse(line, USAGE)),
        }
    }
    Ok(ModuleDirective::SnoopFrrGate {
        v4_list,
        v6_list,
        interval,
        remove_after,
        line,
    })
}

/// `Nd` day literal, inclusive bounds. Deliberately separate from
/// [`parse_duration`]: teaching that one about days would make every
/// existing caller (attach-settle-time, guard rates) silently accept
/// day-scale values none of them should.
fn parse_days(tok: &str, min_days: u64, max_days: u64) -> Result<Duration, String> {
    let Some(n) = tok.strip_suffix('d') else {
        return Err(format!("`{tok}` must be a whole number of days, e.g. 14d"));
    };
    let days: u64 = n
        .parse()
        .map_err(|e| format!("bad day count `{tok}`: {e}"))?;
    if !(min_days..=max_days).contains(&days) {
        return Err(format!("must be between {min_days}d and {max_days}d"));
    }
    Ok(Duration::from_secs(days * 86_400))
}

/// A `Ns`/`Nms` duration with inclusive second bounds; error as a
/// `String` so it composes inside [`parse_single_arg`] closures.
fn parse_bounded_secs(
    line: usize,
    tok: &str,
    context: &str,
    min_secs: u64,
    max_secs: u64,
) -> Result<Duration, String> {
    let d = parse_duration(line, tok, context).map_err(|e| e.to_string())?;
    if d < Duration::from_secs(min_secs) || d > Duration::from_secs(max_secs) {
        return Err(format!(
            "{context} must be between {min_secs}s and {max_secs}s"
        ));
    }
    Ok(d)
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

/// Upper bound on `coalesce` `*-usecs`. A 10 ms interrupt timer is
/// already a latency fault on a forwarding path (the measured win is
/// at 50 µs); past it is read as a typo, not a tuning.
pub const COALESCE_MAX_USECS: u32 = 10_000;
/// Upper bound on `coalesce` `*-frames`: the largest descriptor ring
/// the generic-mode runbook sizes (`ethtool -G ... 32768`). A count
/// threshold past the ring can never be reached.
pub const COALESCE_MAX_FRAMES: u32 = 32_768;

/// `coalesce <key> <n> [<key> <n>...]`: keyword/value pairs in any
/// order, each key at most once, at least one pair.
fn parse_coalesce<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    use crate::ethtool::{CoalesceField, CoalesceSpec};
    const USAGE: &str =
        "form: `coalesce [rx-usecs <n>] [rx-frames <n>] [tx-usecs <n>] [tx-frames <n>]`";
    let mut spec = CoalesceSpec::default();
    while let Some(key) = rest.next() {
        let field = CoalesceField::from_keyword(key).ok_or_else(|| {
            ConfigError::parse(
                line,
                format!("coalesce: unknown parameter `{key}` ({USAGE})"),
            )
        })?;
        if spec.get(field).is_some() {
            return Err(ConfigError::parse(
                line,
                format!("coalesce: `{key}` given twice"),
            ));
        }
        let tok = rest.next().ok_or_else(|| {
            ConfigError::parse(line, format!("coalesce: `{key}` requires a value"))
        })?;
        // A u32 parse refuses negatives and fractions outright.
        let v: u32 = tok.parse().map_err(|_| {
            ConfigError::parse(
                line,
                format!("coalesce: `{key}` expects a non-negative integer, got `{tok}`"),
            )
        })?;
        let max = match field {
            CoalesceField::RxUsecs | CoalesceField::TxUsecs => COALESCE_MAX_USECS,
            CoalesceField::RxFrames | CoalesceField::TxFrames => COALESCE_MAX_FRAMES,
        };
        if v > max {
            return Err(ConfigError::parse(
                line,
                format!("coalesce: `{key} {v}` out of range [0, {max}]"),
            ));
        }
        spec.set(field, Some(v));
    }
    if spec.is_empty() {
        return Err(ConfigError::parse(
            line,
            format!("coalesce requires at least one parameter ({USAGE})"),
        ));
    }
    Ok(ModuleDirective::Coalesce { spec, line })
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

/// Parse `integrity-authority <birdc [path] | frr <opts> | none>`.
///
/// - `birdc` with no path uses the default; `birdc /some/birdc`
///   overrides it.
/// - `frr upstream <ip> [upstream <ip>...] [families v4|v6|v4,v6]
///   [vtysh <path>]`. At least one upstream is mandatory — see
///   [`IntegrityAuthoritySpec::Frr`] for why a count with no readiness
///   evidence is not an authority.
/// - `none` declares that no local authority attests this mirror.
///
/// See [`IntegrityAuthoritySpec`] for why this is a stated fact rather
/// than something inferred from the route source.
fn parse_integrity_authority<'a>(
    line: usize,
    mut rest: impl Iterator<Item = &'a str>,
) -> Result<ModuleDirective, ConfigError> {
    const USAGE: &str = "`birdc [path]`, `frr upstream <ip> [upstream <ip>...] \
                         [families v4|v6|v4,v6] [vtysh <path>]`, or `none`";
    let kind = rest
        .next()
        .ok_or_else(|| ConfigError::parse(line, format!("integrity-authority requires {USAGE}")))?;
    let spec = match kind {
        "birdc" => {
            let path = match rest.next() {
                Some(raw) => Some(validate_safe_path(line, "integrity-authority birdc", raw)?),
                None => None,
            };
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "integrity-authority takes at most `birdc <path>` — extra arguments are \
                     not allowed",
                ));
            }
            IntegrityAuthoritySpec::Birdc { path }
        }
        "frr" => parse_integrity_authority_frr(line, rest)?,
        "none" => {
            if rest.next().is_some() {
                return Err(ConfigError::parse(
                    line,
                    "integrity-authority none takes no arguments",
                ));
            }
            IntegrityAuthoritySpec::None
        }
        other => {
            return Err(ConfigError::parse(
                line,
                format!("integrity-authority expects {USAGE}, got `{other}`"),
            ))
        }
    };
    Ok(ModuleDirective::IntegrityAuthority(spec))
}

/// The tail of `integrity-authority frr ...`.
fn parse_integrity_authority_frr<'a>(
    line: usize,
    rest: impl Iterator<Item = &'a str>,
) -> Result<IntegrityAuthoritySpec, ConfigError> {
    let mut vtysh = None;
    let mut interval_secs: Option<u64> = None;
    let mut upstreams: Vec<AuthorityUpstream> = Vec::new();
    let mut rest = rest.peekable();

    while let Some(tok) = rest.next() {
        match tok {
            "upstream" => {
                let raw = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "integrity-authority frr: `upstream` needs an IP")
                })?;
                let addr: IpAddr = raw.parse().map_err(|_| {
                    ConfigError::parse(
                        line,
                        format!("integrity-authority frr: `{raw}` is not an IP address"),
                    )
                })?;
                if upstreams.iter().any(|u| u.addr == addr) {
                    return Err(ConfigError::parse(
                        line,
                        format!("integrity-authority frr: upstream {addr} listed twice"),
                    ));
                }
                upstreams.push(AuthorityUpstream {
                    addr,
                    families: Vec::new(),
                });
            }
            // Binds to the upstream it follows. Positional rather than
            // free-floating because a global list cannot describe a
            // deployment whose families arrive over separate sessions,
            // and a list that sometimes means "this peer" and sometimes
            // "all peers" is worse than either.
            "families" => {
                let Some(current) = upstreams.last_mut() else {
                    return Err(ConfigError::parse(
                        line,
                        "integrity-authority frr: `families` must follow the `upstream` it \
                         describes — families are per-session, because IPv4 and IPv6 can \
                         arrive over different ones",
                    ));
                };
                if !current.families.is_empty() {
                    return Err(ConfigError::parse(
                        line,
                        format!(
                            "integrity-authority frr: `families` given twice for upstream {}",
                            current.addr
                        ),
                    ));
                }
                let raw = rest.next().ok_or_else(|| {
                    ConfigError::parse(
                        line,
                        "integrity-authority frr: `families` needs v4, v6, or v4,v6",
                    )
                })?;
                for part in raw.split(',') {
                    let f = match part {
                        "v4" => AuthorityFamily::V4,
                        "v6" => AuthorityFamily::V6,
                        other => {
                            return Err(ConfigError::parse(
                                line,
                                format!(
                                    "integrity-authority frr: unknown family `{other}` \
                                     (expected v4 or v6)"
                                ),
                            ))
                        }
                    };
                    if current.families.contains(&f) {
                        return Err(ConfigError::parse(
                            line,
                            format!("integrity-authority frr: family `{part}` listed twice"),
                        ));
                    }
                    current.families.push(f);
                }
                if current.families.is_empty() {
                    return Err(ConfigError::parse(
                        line,
                        "integrity-authority frr: `families` must name at least one family",
                    ));
                }
            }
            "interval" => {
                if interval_secs.is_some() {
                    return Err(ConfigError::parse(
                        line,
                        "integrity-authority frr: `interval` given twice",
                    ));
                }
                let raw = rest.next().ok_or_else(|| {
                    ConfigError::parse(
                        line,
                        "integrity-authority frr: `interval` needs a number of seconds",
                    )
                })?;
                let secs: u64 = raw.parse().map_err(|_| {
                    ConfigError::parse(
                        line,
                        format!(
                            "integrity-authority frr: interval `{raw}` is not a whole number \
                             of seconds"
                        ),
                    )
                })?;
                if !FRR_INTERVAL_SECS.contains(&secs) {
                    return Err(ConfigError::parse(
                        line,
                        format!(
                            "integrity-authority frr: interval {secs}s is outside {}..={}s. \
                             Below the floor a check cannot finish before the next is due; \
                             above the ceiling a report ages past the steering gate's {}s \
                             staleness limit before its successor lands, and the gate would \
                             refuse between checks on a healthy box",
                            FRR_INTERVAL_SECS.start(),
                            FRR_INTERVAL_SECS.end(),
                            crate::fib::STEER_MAX_REPORT_AGE.as_secs()
                        ),
                    ));
                }
                interval_secs = Some(secs);
            }
            "vtysh" => {
                if vtysh.is_some() {
                    return Err(ConfigError::parse(
                        line,
                        "integrity-authority frr: `vtysh` given twice",
                    ));
                }
                let raw = rest.next().ok_or_else(|| {
                    ConfigError::parse(line, "integrity-authority frr: `vtysh` needs a path")
                })?;
                vtysh = Some(validate_safe_path(
                    line,
                    "integrity-authority frr vtysh",
                    raw,
                )?);
            }
            other => {
                return Err(ConfigError::parse(
                    line,
                    format!(
                        "integrity-authority frr: unexpected `{other}` (expected `upstream`, \
                         `families`, `interval`, or `vtysh`)"
                    ),
                ))
            }
        }
    }

    // No upstream means no readiness evidence, and a bare count cannot
    // tell a converged table from one still filling — the two grow
    // together and agree the whole way. Refusing here rather than
    // silently degrading to count-only keeps the variant's guarantee
    // the one its docs claim.
    if upstreams.is_empty() {
        return Err(ConfigError::parse(
            line,
            "integrity-authority frr needs at least one `upstream <ip> families <list>`: the \
             peers whose End-of-RIB proves FRR's own table is loaded. Without one, a prefix \
             count cannot tell a converged table from one still filling from upstream — both \
             sides grow together and the counts agree the whole way. Do NOT list \
             packetframe's own session here; that is the thing being attested",
        ));
    }
    // No default, deliberately. See `AuthorityUpstream`: a wrong guess
    // here is a box that can never attest, discovered during a rollout
    // window rather than at load.
    if let Some(u) = upstreams.iter().find(|u| u.families.is_empty()) {
        return Err(ConfigError::parse(
            line,
            format!(
                "integrity-authority frr: upstream {} needs `families v4`, `families v6` or \
                 `families v4,v6`. There is no default: declaring a family this session does \
                 not carry makes the authority refuse forever (FRR reports no statistics for \
                 it and its End-of-RIB never arrives), and omitting one it does carry would \
                 attest a mirror nobody checked",
                u.addr
            ),
        ));
    }

    Ok(IntegrityAuthoritySpec::Frr {
        vtysh,
        upstreams,
        interval_secs,
    })
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
            "route-source requires a kind + args (e.g. `bgp 127.0.0.1:1179 local-as 65551 peer-as 65551`)",
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
            let mut anyip = false;
            while let Some(key) = rest.next() {
                // `allow-remote` is a no-value flag; everything
                // else takes one argument.
                if key == "allow-remote" {
                    allow_remote = true;
                    continue;
                }
                if key == "anyip" {
                    anyip = true;
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
                                "route-source bgp: unknown key `{other}` (known: local-as, peer-as, router-id, allow-remote, peer-from, peer-ip, anyip)"
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
            // `anyip` describes a non-loopback phantom address, so it
            // inherits allow-remote's obligations (a peer-from ACL on
            // a routable listen). Checked after validate_listener_auth
            // so the operator fixes auth-shape errors first and this
            // one second, not interleaved.
            if anyip && !allow_remote {
                return Err(ConfigError::parse(
                    line,
                    "route-source bgp: `anyip` requires `allow-remote peer-from <cidr>` — \
                     the phantom listen address is non-loopback by definition",
                ));
            }
            if anyip {
                let parsed = addr
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .map_err(|e| {
                        ConfigError::parse(
                            line,
                            format!("route-source bgp: bad listen address `{addr}`: {e}"),
                        )
                    })?;
                let std::net::IpAddr::V4(v4) = parsed else {
                    return Err(ConfigError::parse(
                        line,
                        "route-source bgp: `anyip` supports IPv4 listen addresses only",
                    ));
                };
                // A phantom must be a concrete unicast host: the
                // wildcard would install a meaningless `local
                // 0.0.0.0/32` while binding every interface, and
                // multicast/broadcast can never act as an FRR
                // neighbor — the listener would retry forever.
                if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                    return Err(ConfigError::parse(
                        line,
                        format!(
                            "route-source bgp: `anyip` requires a concrete unicast listen \
                             address, got `{v4}` (unspecified/multicast/broadcast cannot \
                             be a phantom neighbor)"
                        ),
                    ));
                }
            }
            Ok(ModuleDirective::RouteSource(RouteSourceSpec::Bgp {
                addr,
                port,
                local_as,
                peer_as,
                router_id,
                allow_remote,
                peer_from,
                peer_ip,
                anyip,
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
    // Brackets are IPv6 endpoint syntax. A bracketed IPv4 —
    // `[192.0.2.202]:1179` — passed every validation (they all strip
    // brackets) but reached consumers with the brackets stored:
    // SocketAddr parsing silently dropped the feed, and the anyip
    // preflight panicked on an addr its own validator had accepted
    // (review finding, PR #196). Reject the shape by name instead.
    if let Some(inner) = addr.strip_prefix('[').and_then(|a| a.strip_suffix(']')) {
        if inner.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(ConfigError::parse(
                line,
                format!(
                    "route-source {kind_label}: `{addr}` is a bracketed IPv4 address; \
                     brackets are IPv6 syntax — write `{inner}:{port}`"
                ),
            ));
        }
    }
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
  allow-prefix  192.0.2.0/24
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
    fn log_level_as_str_round_trips_through_from_str() {
        for level in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            assert_eq!(level.as_str().parse::<LogLevel>(), Ok(level));
        }
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
    fn attach_tc_mode_parses() {
        let s = "module fast-path\n  attach eth5 tc\n";
        let c = Config::parse(s).unwrap();
        let d = &c.modules[0].directives[0];
        match d {
            ModuleDirective::Attach { iface, mode, .. } => {
                assert_eq!(iface, "eth5");
                assert_eq!(*mode, AttachMode::Tc);
            }
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    #[test]
    fn fib_cache_parses() {
        for (tok, want) in [("on", true), ("off", false)] {
            let s = format!("module fast-path\n  fib-cache {tok}\n");
            let c = Config::parse(&s).unwrap();
            match &c.modules[0].directives[0] {
                ModuleDirective::FibCache(v) => assert_eq!(*v, want),
                other => panic!("expected FibCache, got {other:?}"),
            }
        }
        assert!(Config::parse("module fast-path\n  fib-cache auto\n").is_err());
        assert!(Config::parse("module fast-path\n  fib-cache\n").is_err());
        assert!(Config::parse("module fast-path\n  fib-cache on off\n").is_err());
    }

    fn coalesce_of(body: &str) -> Result<crate::ethtool::CoalesceSpec, String> {
        let s = format!("module fast-path\n  {body}\n");
        let c = Config::parse(&s).map_err(|e| e.to_string())?;
        match &c.modules[0].directives[0] {
            ModuleDirective::Coalesce { spec, line } => {
                assert_eq!(*line, 2);
                Ok(*spec)
            }
            other => panic!("expected Coalesce, got {other:?}"),
        }
    }

    #[test]
    fn coalesce_full_form_parses() {
        let spec = coalesce_of("coalesce rx-usecs 50 rx-frames 32 tx-usecs 50 tx-frames 32")
            .expect("parse");
        assert_eq!(
            spec,
            crate::ethtool::CoalesceSpec {
                rx_usecs: Some(50),
                rx_frames: Some(32),
                tx_usecs: Some(50),
                tx_frames: Some(32),
            }
        );
    }

    #[test]
    fn coalesce_fields_are_optional_and_order_free() {
        let spec = coalesce_of("coalesce tx-frames 16 rx-usecs 0").expect("parse");
        assert_eq!(
            spec,
            crate::ethtool::CoalesceSpec {
                rx_usecs: Some(0),
                tx_frames: Some(16),
                ..Default::default()
            }
        );
        // Bounds are inclusive.
        let spec = coalesce_of(&format!(
            "coalesce rx-usecs {COALESCE_MAX_USECS} rx-frames {COALESCE_MAX_FRAMES}"
        ))
        .expect("parse");
        assert_eq!(spec.rx_usecs, Some(COALESCE_MAX_USECS));
        assert_eq!(spec.rx_frames, Some(COALESCE_MAX_FRAMES));
    }

    #[test]
    fn coalesce_rejects_malformed_lines() {
        for (body, needle) in [
            ("coalesce", "at least one parameter"),
            ("coalesce rx-usecs", "requires a value"),
            ("coalesce rx-usecs -1", "non-negative integer"),
            ("coalesce rx-usecs 2.5", "non-negative integer"),
            ("coalesce rx-usecs fast", "non-negative integer"),
            ("coalesce rx-usecs 10001", "out of range [0, 10000]"),
            ("coalesce tx-frames 32769", "out of range [0, 32768]"),
            ("coalesce rx-usecs 50 rx-usecs 60", "given twice"),
            ("coalesce adaptive-rx on", "unknown parameter `adaptive-rx`"),
            ("coalesce 50", "unknown parameter `50`"),
        ] {
            let e = coalesce_of(body).expect_err(body);
            assert!(e.contains(needle), "{body}: {e}");
        }
    }

    #[test]
    fn coalesce_twice_in_one_section_is_refused() {
        let e = Config::parse("module fast-path\n  coalesce rx-usecs 50\n  coalesce tx-usecs 50\n")
            .expect_err("duplicate");
        let msg = e.to_string();
        assert!(
            msg.contains("line 3") && msg.contains("first on line 2"),
            "{msg}"
        );
    }

    #[test]
    fn bridge_resolve_parses() {
        for (tok, want) in [
            ("auto", ToggleAutoOnOff::Auto),
            ("on", ToggleAutoOnOff::On),
            ("off", ToggleAutoOnOff::Off),
        ] {
            let s = format!("module fast-path\n  bridge-resolve {tok}\n");
            let c = Config::parse(&s).unwrap();
            match &c.modules[0].directives[0] {
                ModuleDirective::BridgeResolve(v) => assert_eq!(*v, want),
                other => panic!("expected BridgeResolve, got {other:?}"),
            }
        }
        assert!(Config::parse("module fast-path\n  bridge-resolve maybe\n").is_err());
        assert!(Config::parse("module fast-path\n  bridge-resolve\n").is_err());
        assert!(Config::parse("module fast-path\n  bridge-resolve on extra\n").is_err());
    }

    #[test]
    fn fdb_pin_parses() {
        for (tok, want) in [
            ("auto", ToggleAutoOnOff::Auto),
            ("on", ToggleAutoOnOff::On),
            ("off", ToggleAutoOnOff::Off),
        ] {
            let s = format!("module fast-path\n  fdb-pin {tok}\n");
            let c = Config::parse(&s).unwrap();
            match &c.modules[0].directives[0] {
                ModuleDirective::FdbPin(v) => assert_eq!(*v, want),
                other => panic!("expected FdbPin, got {other:?}"),
            }
        }
        assert!(Config::parse("module fast-path\n  fdb-pin maybe\n").is_err());
        assert!(Config::parse("module fast-path\n  fdb-pin\n").is_err());
        assert!(Config::parse("module fast-path\n  fdb-pin auto extra\n").is_err());
    }

    #[test]
    fn integrity_authority_frr_parses() {
        let dir = |cfg: &str| Config::parse(cfg).unwrap().modules[0].directives[0].clone();
        let one =
            dir("module fast-path\n  integrity-authority frr upstream 192.0.2.1 families v4,v6\n");
        assert_eq!(
            one,
            ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::Frr {
                vtysh: None,
                upstreams: vec![AuthorityUpstream {
                    addr: "192.0.2.1".parse().unwrap(),
                    families: vec![AuthorityFamily::V4, AuthorityFamily::V6],
                }],
                interval_secs: None,
            })
        );

        let full = dir(
            "module fast-path\n  integrity-authority frr upstream 192.0.2.1 families v4 \
             upstream 2001:db8::1 families v6 vtysh /opt/frr/vtysh interval 15\n",
        );
        match full {
            ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::Frr {
                vtysh,
                upstreams,
                interval_secs,
            }) => {
                assert!(vtysh.is_some());
                assert_eq!(interval_secs, Some(15));
                assert_eq!(
                    upstreams,
                    vec![
                        AuthorityUpstream {
                            addr: "192.0.2.1".parse().unwrap(),
                            families: vec![AuthorityFamily::V4],
                        },
                        AuthorityUpstream {
                            addr: "2001:db8::1".parse().unwrap(),
                            families: vec![AuthorityFamily::V6],
                        },
                    ],
                    "each `families` binds to the upstream it follows — the separate-session \
                     dual-stack shape a single global list could not express"
                );
            }
            other => panic!("expected Frr, got {other:?}"),
        }
    }

    /// `interval` is bounded, and both bounds say why.
    ///
    /// The ceiling is the one that matters: a report older than the
    /// steering gate's staleness limit refuses, so an interval near it
    /// would make a healthy box refuse between every pair of checks.
    #[test]
    fn integrity_authority_frr_interval_is_bounded() {
        let with = |i: &str| {
            Config::parse(&format!(
                "module fast-path\n  integrity-authority frr upstream 192.0.2.1 families v4 \
                 interval {i}\n"
            ))
        };
        let lo = *FRR_INTERVAL_SECS.start();
        let hi = *FRR_INTERVAL_SECS.end();
        assert!(with(&lo.to_string()).is_ok());
        assert!(with(&hi.to_string()).is_ok());
        let e = with(&(hi + 1).to_string()).unwrap_err().to_string();
        assert!(
            e.contains("staleness limit"),
            "say why the ceiling exists: {e}"
        );
        assert!(with(&(lo - 1).to_string()).is_err());
        assert!(with("0").is_err());
        assert!(
            with("15s").is_err(),
            "whole seconds only — a unit suffix is a typo"
        );
        assert!(with("15 interval 20").is_err(), "given twice");
        // The property the ceiling exists for, stated as arithmetic:
        // from a report at t=0, a failed attempt at ~hi and its retry at
        // ~2*hi must still beat the staleness limit, with room left for
        // the checks' own duration.
        let limit = crate::fib::STEER_MAX_REPORT_AGE.as_secs();
        assert!(
            2 * hi < limit,
            "a failed check at the ceiling must not age the retained report out: \
             2 x {hi}s must be under {limit}s"
        );
        assert!(
            limit - 2 * hi >= 120,
            "and leave real time for the two checks themselves, not a sliver"
        );
    }

    /// Changing it is a restart, like every other part of the spec — a
    /// reload that accepted the edit and kept the running checker's old
    /// cadence would be the silent no-op this repo keeps refusing.
    #[test]
    fn integrity_authority_frr_interval_is_restart_only() {
        let spec = |i: Option<u64>| IntegrityAuthoritySpec::Frr {
            vtysh: None,
            upstreams: vec![AuthorityUpstream {
                addr: "192.0.2.1".parse().unwrap(),
                families: vec![AuthorityFamily::V4],
            }],
            interval_secs: i,
        };
        spec(Some(15)).restart_only_delta(&spec(Some(15))).unwrap();
        let e = spec(None).restart_only_delta(&spec(Some(15))).unwrap_err();
        assert!(e.contains("Restart the daemon"), "{e}");
    }

    /// There is no default family set, and the refusal explains why in
    /// both directions.
    ///
    /// The earlier default of `v4,v6` was wrong on an IPv4-only box in
    /// the worst way available: `parse_total_prefixes` refuses a missing
    /// `ipv6Unicast` array and a missing IPv6 End-of-RIB reads as
    /// not-ready, so the authority could never attest anything and
    /// `require-table-complete` deferred forever — the failure the whole
    /// variant exists to prevent, delivered by its own default.
    #[test]
    fn integrity_authority_frr_requires_families_per_upstream() {
        let e = Config::parse("module fast-path\n  integrity-authority frr upstream 192.0.2.1\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("192.0.2.1"), "name the upstream: {e}");
        assert!(e.contains("There is no default"), "{e}");
        assert!(
            e.contains("refuse forever") && e.contains("nobody checked"),
            "both directions of the mistake: {e}"
        );

        // Only the SECOND upstream is missing them — the check is
        // per-upstream, not "at least one has some".
        let e = Config::parse(
            "module fast-path\n  integrity-authority frr upstream 192.0.2.1 families v4 \
             upstream 192.0.2.2\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("192.0.2.2"), "{e}");

        // And `families` before any `upstream` is a positional error
        // rather than a silent global.
        let e = Config::parse(
            "module fast-path\n  integrity-authority frr families v4 upstream 192.0.2.1\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("must follow the `upstream`"), "{e}");
    }

    /// An upstream is mandatory, and the refusal has to say why rather
    /// than quietly degrading to a count-only authority that cannot
    /// tell a converged table from one still filling.
    #[test]
    fn integrity_authority_frr_requires_an_upstream() {
        let e = Config::parse("module fast-path\n  integrity-authority frr\n").unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("at least one `upstream"), "{msg}");
        assert!(
            msg.contains("End-of-RIB"),
            "it must say what an upstream is for: {msg}"
        );
    }

    #[test]
    fn integrity_authority_frr_rejects_junk() {
        for bad in [
            "module fast-path\n  integrity-authority frr upstream nonsense\n",
            "module fast-path\n  integrity-authority frr upstream 192.0.2.1 families v5\n",
            "module fast-path\n  integrity-authority frr upstream 192.0.2.1 upstream 192.0.2.1\n",
            "module fast-path\n  integrity-authority frr upstream 192.0.2.1 wat\n",
            "module fast-path\n  integrity-authority frr upstream\n",
        ] {
            assert!(
                Config::parse(bad).is_err(),
                "should have been refused: {bad}"
            );
        }
    }

    /// `frr` is an authority, so it satisfies the gate that `none`
    /// cannot.
    #[test]
    fn frr_authority_permits_require_table_complete() {
        let cfg = "\
module fast-path
  attach eth2 generic
  allow-prefix 203.0.113.0/24
  forwarding-mode custom-fib
  integrity-authority frr upstream 192.0.2.1 families v4,v6

module vpp-offload
  loopback-address 198.51.100.1/32
  port eth2 cores 1 steer off
  require-table-complete on
";
        assert!(
            Config::parse(cfg).is_ok(),
            "an FRR authority must satisfy require-table-complete"
        );
    }

    #[test]
    fn integrity_authority_parses() {
        let birdc_default = Config::parse("module fast-path\n  integrity-authority birdc\n")
            .unwrap()
            .modules[0]
            .directives[0]
            .clone();
        assert_eq!(
            birdc_default,
            ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::Birdc { path: None })
        );

        let birdc_path =
            Config::parse("module fast-path\n  integrity-authority birdc /opt/bird/birdc\n")
                .unwrap()
                .modules[0]
                .directives[0]
                .clone();
        assert!(matches!(
            birdc_path,
            ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::Birdc { path: Some(_) })
        ));

        let none = Config::parse("module fast-path\n  integrity-authority none\n")
            .unwrap()
            .modules[0]
            .directives[0]
            .clone();
        assert_eq!(
            none,
            ModuleDirective::IntegrityAuthority(IntegrityAuthoritySpec::None)
        );

        for bad in [
            "module fast-path\n  integrity-authority\n",
            "module fast-path\n  integrity-authority bmp\n",
            "module fast-path\n  integrity-authority none extra\n",
            "module fast-path\n  integrity-authority birdc /a /b\n",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    /// A reload may not move the authority under a running checker.
    ///
    /// The directive is consumed once, when the route controller
    /// starts. Accepting the edit and continuing to compare against the
    /// old authority is the silent no-op class — and this is precisely
    /// the directive the mismatch remedy tells an operator to change,
    /// so "it returned OK" would read as "it took effect".
    #[test]
    fn integrity_authority_is_restart_only() {
        let birdc = IntegrityAuthoritySpec::Birdc { path: None };
        let none = IntegrityAuthoritySpec::None;
        let other = IntegrityAuthoritySpec::Birdc {
            path: Some(PathBuf::from("/opt/bird/birdc")),
        };

        // Unchanged reloads are fine — the common case, every SIGHUP
        // that edits an allowlist.
        birdc.restart_only_delta(&birdc).unwrap();
        none.restart_only_delta(&none).unwrap();

        // Every real change is refused, in both directions, including a
        // path swap that keeps the same variant.
        for (from, to) in [
            (&birdc, &none),
            (&none, &birdc),
            (&birdc, &other),
            (&other, &none),
        ] {
            let err = from.restart_only_delta(to).unwrap_err();
            assert!(
                err.contains("read once") && err.contains("Restart the daemon"),
                "a refused change must say why and what to do: {err}"
            );
        }
    }

    /// `integrity-authority frr` over a BMP feed is refused, and the
    /// message says it is a gap rather than a rule.
    ///
    /// Two of the FRR authority's three conjuncts work fine over BMP —
    /// the per-AF counts and the upstreams' End-of-RIB are read from FRR
    /// and say nothing about how the mirror is fed. Export-policy
    /// validation does not: over BMP there is no session to this
    /// packetframe, and what narrows the feed is FRR's `bmp targets`
    /// grammar, which nothing on the reference fleet has been measured
    /// against. Accepting the combination would silently drop the one
    /// conjunct the counts cannot substitute for, and hand back a green
    /// row for a weaker guarantee than the operator asked for.
    #[test]
    fn the_frr_authority_is_refused_over_a_bmp_feed() {
        let bmp = "module fast-path\n  forwarding-mode custom-fib\n  \
                   route-source bmp 127.0.0.1:1790 require-loc-rib\n  \
                   integrity-authority frr upstream 192.0.2.1 families v4,v6\n\
                   module vpp-offload\n  loopback-address 192.0.2.9/32\n  \
                   port eth1 cores 1 steer off\n";
        let err = Config::parse(bmp)
            .unwrap()
            .validate_fast_path()
            .expect_err("must refuse");
        let err = format!("{err}");
        assert!(
            err.contains("bmp targets"),
            "name what it cannot read: {err}"
        );
        assert!(
            err.contains("route-source bgp"),
            "and the way forward: {err}"
        );

        // The same authority over the BGP feed it was designed for is
        // accepted — and satisfies `require-table-complete on`, which
        // is the whole point of implementing it.
        let bgp = bmp.replace(
            "route-source bmp 127.0.0.1:1790 require-loc-rib",
            "route-source bgp 127.0.0.1:1179 local-as 64512 peer-as 64512",
        );
        Config::parse(&bgp)
            .unwrap()
            .validate_fast_path()
            .expect("frr over bgp is the supported shape");

        // And it runs for a config with NO vpp-offload section at all,
        // which is the hole this moved out of `validate_vpp_offload` to
        // close: that one returns immediately when the section is
        // absent, so a fast-path-only config reached the loader, failed
        // to spawn an authority, logged an internal error and ran
        // unattested.
        let fast_path_only = bmp
            .split("module vpp-offload")
            .next()
            .expect("split")
            .to_string();
        assert!(
            Config::parse(&fast_path_only)
                .unwrap()
                .validate_fast_path()
                .is_err(),
            "the refusal must not depend on a vpp-offload section being present"
        );
    }

    /// packetframe's own listen address must not appear as an upstream.
    ///
    /// Circular: the authority would wait for End-of-RIB from the
    /// session it is supposed to be attesting, which packetframe never
    /// sends — so the peer reads not-ready on every check, eligibility
    /// is revoked forever, and the completeness gate defers every steer.
    /// It parses, and it passes feasibility (FRR really does know that
    /// neighbor), so this is the only place it can be caught before a
    /// rollout window.
    #[test]
    fn the_frr_authority_rejects_packetframes_own_session_as_an_upstream() {
        let cfg = "module fast-path\n  forwarding-mode custom-fib\n  \
                   route-source bgp 127.0.0.1:1179 local-as 64512 peer-as 64512\n  \
                   integrity-authority frr upstream 127.0.0.1 families v4\n";
        let err = Config::parse(cfg)
            .unwrap()
            .validate_fast_path()
            .expect_err("must refuse the circular declaration")
            .to_string();
        assert!(err.contains("127.0.0.1"), "{err}");
        assert!(
            err.contains("the session being attested"),
            "say why it is circular: {err}"
        );
        assert!(
            err.contains("List the peers that feed FRR"),
            "and what to write instead: {err}"
        );

        // A different upstream on the same box is fine.
        let ok = cfg.replace("upstream 127.0.0.1", "upstream 192.0.2.1");
        Config::parse(&ok).unwrap().validate_fast_path().unwrap();
    }

    /// `require-table-complete on` + `integrity-authority none` is a
    /// config that can never permit a first steer, so it is refused at
    /// load rather than discovered as a canary that defers forever.
    #[test]
    fn require_table_complete_needs_an_authority() {
        let base = "module fast-path\n  forwarding-mode custom-fib\n  \
                    route-source bgp 127.0.0.1:1179 local-as 1 peer-as 1\n  \
                    integrity-authority none\n\
                    module vpp-offload\n  loopback-address 192.0.2.1/32\n  \
                    port eth1 cores 1 steer off\n";

        // `require-table-complete` defaults ON, so the bare config is
        // already the conflict.
        let cfg = Config::parse(base).unwrap();
        let err = cfg.validate_vpp_offload().unwrap_err();
        assert!(
            format!("{err}").contains("no authority to attest completeness"),
            "{err}"
        );

        // Opting the gate out resolves it.
        let ok = base.replace(
            "port eth1 cores 1 steer off\n",
            "port eth1 cores 1 steer off\n  require-table-complete off\n",
        );
        Config::parse(&ok).unwrap().validate_vpp_offload().unwrap();

        // Naming an authority resolves it too.
        let ok2 = base.replace("integrity-authority none\n", "integrity-authority birdc\n");
        Config::parse(&ok2).unwrap().validate_vpp_offload().unwrap();
    }

    /// `steer-direction` parses its three values and rejects anything
    /// else by name — a typo'd direction silently defaulting to `both`
    /// would double the MCAM cost AND divert the inbound direction on
    /// a service edge, which is the misconfiguration the directive
    /// exists to prevent.
    #[test]
    fn steer_direction_parses_and_rejects() {
        for (txt, want) in [
            ("src", VppSteerDirection::Src),
            ("dst", VppSteerDirection::Dst),
            ("both", VppSteerDirection::Both),
        ] {
            let s = format!("module vpp-offload\n  steer-direction {txt}\n");
            let c = Config::parse(&s).unwrap();
            match &c.modules[0].directives[0] {
                ModuleDirective::VppSteerDirection(d) => assert_eq!(*d, want),
                other => panic!("expected VppSteerDirection, got {other:?}"),
            }
        }
        let e = Config::parse("module vpp-offload\n  steer-direction inbound\n").unwrap_err();
        assert!(format!("{e}").contains("expects src|dst|both"), "{e}");
    }

    #[test]
    fn vpp_port_parses() {
        let s = "module vpp-offload\n  port eth4 cores 2 steer off\n  port eth5 cores 1 steer on\n";
        let c = Config::parse(s).unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppPort {
                iface,
                cores,
                steer,
                ..
            } => {
                assert_eq!(iface, "eth4");
                assert_eq!(*cores, 2);
                assert!(!steer);
            }
            other => panic!("expected VppPort, got {other:?}"),
        }
        match &c.modules[0].directives[1] {
            ModuleDirective::VppPort { steer, .. } => assert!(steer),
            other => panic!("expected VppPort, got {other:?}"),
        }
        // Malformed variants: missing keywords, bad cores, trailing junk.
        for bad in [
            "module vpp-offload\n  port eth4\n",
            "module vpp-offload\n  port eth4 cores -1 steer off\n",
            "module vpp-offload\n  port eth4 cores many steer off\n",
            "module vpp-offload\n  port eth4 cores 1\n",
            "module vpp-offload\n  port eth4 cores 1 steer maybe\n",
            "module vpp-offload\n  port eth4 cores 1 steer on extra\n",
            "module vpp-offload\n  port eth4 steer on cores 1\n",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    /// `cores 0` is an egress-only member: it parses, and validates
    /// while unsteered alongside a steered port that has its own core.
    #[test]
    fn vpp_port_cores_zero_parses_and_validates_unsteered() {
        let s = "module fast-path\n  forwarding-mode custom-fib\n  attach eth4 generic\n  \
                 attach eth5 generic\n\nmodule vpp-offload\n  \
                 loopback-address 198.51.100.1/32\n  port eth4 cores 0 steer off\n  \
                 port eth5 cores 1 steer on\n";
        let c = Config::parse(s).unwrap();
        let vpp = c.modules.iter().find(|m| m.name == "vpp-offload").unwrap();
        match &vpp.directives[1] {
            ModuleDirective::VppPort {
                iface,
                cores,
                steer,
                ..
            } => {
                assert_eq!(iface, "eth4");
                assert_eq!(*cores, 0);
                assert!(!steer);
            }
            other => panic!("expected VppPort, got {other:?}"),
        }
        c.validate_vpp_offload().unwrap();
    }

    /// A port with no worker of its own cannot take steered traffic;
    /// the refusal names the port and the remedy. Reconfigure runs the
    /// same validator, so this is also the SIGHUP refusal.
    #[test]
    fn vpp_port_cores_zero_with_steer_on_is_refused() {
        let s = "module fast-path\n  forwarding-mode custom-fib\n  attach eth4 generic\n  \
                 attach eth5 generic\n\nmodule vpp-offload\n  \
                 loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer off\n  \
                 port eth5 cores 0 steer on\n";
        let err = Config::parse(s)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err()
            .to_string();
        assert!(err.contains("port eth5"), "{err}");
        assert!(err.contains("cores 0"), "{err}");
        assert!(err.contains("cannot take steered traffic"), "{err}");
        assert!(err.contains("cores 1"), "{err}");
        assert!(err.contains("restart-only"), "{err}");
    }

    #[test]
    fn vpp_worker_count_adds_one_shared_worker_for_cores_zero_ports() {
        assert_eq!(vpp_worker_count([]), 0);
        assert_eq!(vpp_worker_count([1, 2]), 3);
        // Any number of cores-0 ports share ONE worker.
        assert_eq!(vpp_worker_count([0]), 1);
        assert_eq!(vpp_worker_count([0, 0, 0]), 1);
        assert_eq!(vpp_worker_count([1, 0, 0, 0]), 2);
        assert_eq!(vpp_worker_count([0, 2, 0, 1]), 4);
    }

    /// `steer-exempt` exists because of w23 on the primary
    /// (2026-08-14): 110,917 locally-terminating packets blackholed in
    /// five steered minutes — traffic whose destination is the router
    /// itself has to stay on the kernel path.
    #[test]
    fn steer_exempt_parses_and_duplicates_are_refused() {
        let s = "module vpp-offload\n  steer-exempt 192.0.2.1/32\n  steer-exempt 198.51.100.1/32\n";
        let c = Config::parse(s).unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppSteerExempt(p) => {
                assert_eq!(p.addr, std::net::Ipv4Addr::new(192, 0, 2, 1));
                assert_eq!(p.prefix_len, 32);
            }
            other => panic!("expected VppSteerExempt, got {other:?}"),
        }
        assert!(Config::parse("module vpp-offload\n  steer-exempt not-an-ip\n").is_err());

        // The duplicate refusal needs a full valid section around it,
        // because validate_vpp_offload runs after parse.
        let dup = "module fast-path\n  attach eth4 generic\n  allow-prefix 10.0.0.0/8\n\
                   module vpp-offload\n  loopback-address 198.51.100.254/32\n\
                   port eth4 cores 1 steer off\n\
                   steer-exempt 198.51.100.1/32\n  steer-exempt 198.51.100.1/32\n";
        let e = Config::parse(dup)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(
            format!("{e}").contains("duplicate `steer-exempt 198.51.100.1/32`"),
            "{e}"
        );
    }

    /// The `vlans` tail exists because of w20 on the primary
    /// (2026-08-14): steering a trunk port without dot1q subifs
    /// punted 8.7M frames in two minutes. A port line without it
    /// still parses — untagged ports need no declaration.
    #[test]
    fn vpp_port_vlans_parse() {
        let s = "module vpp-offload\n  port eth4 cores 1 steer off vlans 88,1337\n";
        let c = Config::parse(s).unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppPort { vlans, .. } => assert_eq!(vlans, &[88, 1337]),
            other => panic!("expected VppPort, got {other:?}"),
        }
        // No vlans clause → empty list, not an error.
        let c = Config::parse("module vpp-offload\n  port eth4 cores 1 steer off\n").unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppPort { vlans, .. } => assert!(vlans.is_empty()),
            other => panic!("expected VppPort, got {other:?}"),
        }
        for bad in [
            "module vpp-offload\n  port eth4 cores 1 steer off vlans\n",
            "module vpp-offload\n  port eth4 cores 1 steer off vlans 0\n",
            "module vpp-offload\n  port eth4 cores 1 steer off vlans 4095\n",
            "module vpp-offload\n  port eth4 cores 1 steer off vlans 88,88\n",
            "module vpp-offload\n  port eth4 cores 1 steer off vlans 88,\n",
            "module vpp-offload\n  port eth4 cores 1 steer off vlans 88 99\n",
            "module vpp-offload\n  port eth4 cores 1 steer off tags 88\n",
            "module vpp-offload\n  port eth4 cores 1 steer off vlans all,88\n",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject: {bad}");
        }
        // `vlans all` → the flag, and no explicit list.
        let c = Config::parse(
            "module vpp-offload\n  port eth4 cores 1 steer off vlans all direction both\n",
        )
        .unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppPort {
                vlans, vlans_all, ..
            } => assert!(vlans.is_empty() && *vlans_all),
            other => panic!("expected VppPort, got {other:?}"),
        }
    }

    #[test]
    fn vpp_port_direction_parses() {
        // With and without a vlans clause; absent = None (global wins).
        let s = "module vpp-offload\n  port eth3 cores 1 steer off direction dst\n\
                 port eth4 cores 1 steer off vlans 88,1337 direction src\n\
                 port eth5 cores 1 steer off\n";
        let c = Config::parse(s).unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppPort { direction, .. } => {
                assert_eq!(*direction, Some(VppSteerDirection::Dst));
            }
            other => panic!("expected VppPort, got {other:?}"),
        }
        match &c.modules[0].directives[1] {
            ModuleDirective::VppPort {
                vlans, direction, ..
            } => {
                assert_eq!(vlans, &[88, 1337]);
                assert_eq!(*direction, Some(VppSteerDirection::Src));
            }
            other => panic!("expected VppPort, got {other:?}"),
        }
        match &c.modules[0].directives[2] {
            ModuleDirective::VppPort { direction, .. } => assert_eq!(*direction, None),
            other => panic!("expected VppPort, got {other:?}"),
        }
        for bad in [
            "module vpp-offload\n  port eth3 cores 1 steer off direction\n",
            "module vpp-offload\n  port eth3 cores 1 steer off direction inbound\n",
            // direction must follow vlans, not precede it
            "module vpp-offload\n  port eth3 cores 1 steer off direction dst vlans 88\n",
            "module vpp-offload\n  port eth3 cores 1 steer off direction dst extra\n",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn local_route_parses_and_rejects_malformed() {
        let s = "module vpp-offload\n  local-route 192.0.2.0/24 port eth4 vlan 1337\n";
        let c = Config::parse(s).unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::VppLocalRoute {
                prefix,
                iface,
                vlan,
                ..
            } => {
                assert_eq!(prefix.addr, std::net::Ipv4Addr::new(192, 0, 2, 0));
                assert_eq!(prefix.prefix_len, 24);
                assert_eq!(iface, "eth4");
                assert_eq!(*vlan, 1337);
            }
            other => panic!("expected VppLocalRoute, got {other:?}"),
        }
        for bad in [
            "module vpp-offload\n  local-route\n",
            "module vpp-offload\n  local-route 192.0.2.0/24\n",
            "module vpp-offload\n  local-route 192.0.2.0/24 port eth4\n",
            "module vpp-offload\n  local-route 192.0.2.0/24 port eth4 vlan\n",
            "module vpp-offload\n  local-route 192.0.2.0/24 port eth4 vlan 0\n",
            "module vpp-offload\n  local-route 192.0.2.0/24 port eth4 vlan 4095\n",
            "module vpp-offload\n  local-route 192.0.2.0/24 vlan 1337 port eth4\n",
            "module vpp-offload\n  local-route not-a-cidr port eth4 vlan 1337\n",
            "module vpp-offload\n  local-route 192.0.2.0/24 port eth4 vlan 1337 x\n",
        ] {
            assert!(Config::parse(bad).is_err(), "should reject: {bad}");
        }
    }

    /// The structural rules hold with steering off everywhere: the
    /// attached route and neighbour mirror install at attach, so a
    /// broken declaration is a broken attach.
    #[test]
    fn local_route_cross_validation() {
        let base =
            "module fast-path\n  attach eth4 generic\n  local-prefix 192.0.2.0/24 via br1337\n\n\
                    module vpp-offload\n  loopback-address 198.51.100.254/32\n";

        // Happy: port declares the vlan, prefix inside the local-prefix.
        let good = format!(
            "{base}  port eth4 cores 1 steer off vlans 1337\n  \
             local-route 192.0.2.0/24 port eth4 vlan 1337\n"
        );
        Config::parse(&good)
            .unwrap()
            .validate_vpp_offload()
            .unwrap();

        // Port named by the local-route has no port line.
        let no_port = format!(
            "{base}  port eth4 cores 1 steer off vlans 1337\n  \
             local-route 192.0.2.0/24 port eth9 vlan 1337\n"
        );
        let e = Config::parse(&no_port)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(format!("{e}").contains("no `port eth9` line"), "{e}");

        // The port exists but does not declare the vlan.
        let no_vlan = format!(
            "{base}  port eth4 cores 1 steer off vlans 88\n  \
             local-route 192.0.2.0/24 port eth4 vlan 1337\n"
        );
        let e = Config::parse(&no_vlan)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(format!("{e}").contains("does not declare vlan 1337"), "{e}");

        // Not inside any fast-path local-prefix: tier disagreement.
        let no_lp = format!(
            "{base}  port eth4 cores 1 steer off vlans 1337\n  \
             local-route 198.18.0.0/24 port eth4 vlan 1337\n"
        );
        let e = Config::parse(&no_lp)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(format!("{e}").contains("local-prefix"), "{e}");

        // Overlapping local-routes: refused.
        let overlap = format!(
            "{base}  port eth4 cores 1 steer off vlans 88,1337\n  \
             local-route 192.0.2.0/24 port eth4 vlan 1337\n  \
             local-route 192.0.2.0/25 port eth4 vlan 88\n"
        );
        let e = Config::parse(&overlap)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(format!("{e}").contains("overlaps"), "{e}");
    }

    /// dst steering into VPP without local delivery for a steerable
    /// local prefix is a 100%-inbound blackhole (the w20 shape), so it
    /// is a load-time refusal. Pure transit needs no local-routes.
    #[test]
    fn dst_direction_requires_local_route_coverage() {
        let fp = "module fast-path\n  forwarding-mode custom-fib\n  attach eth3 generic\n  \
                  attach eth4 generic\n  allow-prefix 192.0.2.0/24\n  \
                  local-prefix 192.0.2.0/24 via br1337\n\n";
        let vpp_base = "module vpp-offload\n  loopback-address 198.51.100.254/32\n  \
                        port eth3 cores 1 steer on direction dst\n";

        // dst steering, steerable local prefix, no local-route: refused.
        let uncovered = format!("{fp}{vpp_base}  port eth4 cores 1 steer off vlans 1337\n");
        let e = Config::parse(&uncovered)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(format!("{e}").contains("not fully covered"), "{e}");

        // Same but covered: valid.
        let covered = format!(
            "{fp}{vpp_base}  port eth4 cores 1 steer off vlans 1337\n  \
             local-route 192.0.2.0/24 port eth4 vlan 1337\n"
        );
        Config::parse(&covered)
            .unwrap()
            .validate_vpp_offload()
            .unwrap();

        // Partial tiling: one /25 present, the other missing → refused;
        // both present → the pair covers the /24 and it is valid.
        let half = format!(
            "{fp}{vpp_base}  port eth4 cores 1 steer off vlans 88,1337\n  \
             local-route 192.0.2.0/25 port eth4 vlan 1337\n"
        );
        assert!(Config::parse(&half)
            .unwrap()
            .validate_vpp_offload()
            .is_err());
        let tiled = format!(
            "{fp}{vpp_base}  port eth4 cores 1 steer off vlans 88,1337\n  \
             local-route 192.0.2.0/25 port eth4 vlan 1337\n  \
             local-route 192.0.2.128/25 port eth4 vlan 88\n"
        );
        Config::parse(&tiled)
            .unwrap()
            .validate_vpp_offload()
            .unwrap();

        // src steering never needs coverage.
        let src = format!(
            "{fp}module vpp-offload\n  loopback-address 198.51.100.254/32\n  \
             port eth3 cores 1 steer on direction src\n  port eth4 cores 1 steer off\n"
        );
        Config::parse(&src).unwrap().validate_vpp_offload().unwrap();

        // dst steering with no local prefix in the allowlist's path
        // (pure transit): nothing to cover, valid. The global default
        // direction (`both`) triggers coverage exactly like `dst`.
        let transit = "module fast-path\n  forwarding-mode custom-fib\n  attach eth3 generic\n  \
                       allow-prefix 198.18.0.0/15\n\n\
                       module vpp-offload\n  loopback-address 198.51.100.254/32\n  \
                       port eth3 cores 1 steer on\n";
        Config::parse(transit)
            .unwrap()
            .validate_vpp_offload()
            .unwrap();
    }

    #[test]
    fn vpp_sizing_directives_parse() {
        let s = "module vpp-offload\n  expected-routes 1200000\n  hugepages 8\n  vpp-binary /usr/bin/vpp\n";
        let c = Config::parse(s).unwrap();
        assert!(matches!(
            c.modules[0].directives[0],
            ModuleDirective::ExpectedRoutes(1_200_000)
        ));
        assert!(matches!(
            c.modules[0].directives[1],
            ModuleDirective::VppHugepages(8)
        ));
        assert!(Config::parse("module vpp-offload\n  expected-routes 0\n").is_err());
        assert!(Config::parse("module vpp-offload\n  hugepages 0\n").is_err());
    }

    #[test]
    fn steer_capacity_parses_within_its_bound() {
        let c = Config::parse("module vpp-offload\n  steer-capacity 64\n").unwrap();
        assert!(matches!(
            c.modules[0].directives[0],
            ModuleDirective::VppSteerCapacity(64)
        ));
        let max = format!("module vpp-offload\n  steer-capacity {VPP_MAX_STEER_CAPACITY}\n");
        assert!(Config::parse(&max).is_ok());
        for bad in ["0", "257", "-1", "lots", "64 128"] {
            let s = format!("module vpp-offload\n  steer-capacity {bad}\n");
            assert!(
                Config::parse(&s).is_err(),
                "`steer-capacity {bad}` must be refused"
            );
        }
    }

    #[test]
    fn vpp_offload_cross_validation() {
        // Membership-only (no steer) with a fast-path section: valid.
        let staging = "module fast-path\n  attach eth4 generic\n\nmodule vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer off\n";
        Config::parse(staging)
            .unwrap()
            .validate_vpp_offload()
            .unwrap();

        // vpp-offload without fast-path: rejected.
        let orphan = "module vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer off\n";
        assert!(Config::parse(orphan)
            .unwrap()
            .validate_vpp_offload()
            .is_err());

        // Steering without custom-fib: rejected.
        let no_cfib = "module fast-path\n  attach eth4 generic\n\nmodule vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer on\n";
        assert!(Config::parse(no_cfib)
            .unwrap()
            .validate_vpp_offload()
            .is_err());

        // Steering with a fast-path attach port missing membership: rejected.
        let missing_member = "module fast-path\n  forwarding-mode custom-fib\n  attach eth4 generic\n  attach eth5 generic\n\nmodule vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth5 cores 1 steer on\n";
        assert!(Config::parse(missing_member)
            .unwrap()
            .validate_vpp_offload()
            .is_err());

        // Full membership + steering + custom-fib: valid.
        let good = "module fast-path\n  forwarding-mode custom-fib\n  attach eth4 generic\n  attach eth5 generic\n\nmodule vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer off\n  port eth5 cores 1 steer on\n";
        Config::parse(good).unwrap().validate_vpp_offload().unwrap();

        // Duplicate port line: rejected.
        let dup = "module fast-path\n  attach eth4 generic\n\nmodule vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer off\n  port eth4 cores 2 steer off\n";
        assert!(Config::parse(dup).unwrap().validate_vpp_offload().is_err());

        // Empty section: rejected here, so `feasibility` and `run`
        // reach the same verdict on the same file.
        let empty = "module fast-path\n  attach eth4 generic\n\nmodule vpp-offload\n  loopback-address 198.51.100.1/32\n  expected-routes 100\n";
        let err = Config::parse(empty)
            .unwrap()
            .validate_vpp_offload()
            .unwrap_err();
        assert!(format!("{err}").contains("no `port` lines"), "{err}");
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

    // --- Prefix containment helpers -------------------------------------
    //
    // These back `LocalPrefixSpec::contains` in the fast-path resolver
    // and `prefix_contains` in linux_impl, so the `/0` and `/max` cases
    // are guarding real shift-overflow traps, not hypotheticals.

    fn v4(s: &str) -> Ipv4Prefix {
        s.parse().expect("v4 prefix")
    }

    fn v6(s: &str) -> Ipv6Prefix {
        s.parse().expect("v6 prefix")
    }

    #[test]
    fn v4_contains_addr_basic() {
        let p = v4("192.0.2.64/26");
        assert!(p.contains_addr("192.0.2.64".parse().unwrap()));
        assert!(p.contains_addr("192.0.2.74".parse().unwrap()));
        assert!(p.contains_addr("192.0.2.127".parse().unwrap()));
        assert!(!p.contains_addr("192.0.2.128".parse().unwrap()));
        assert!(!p.contains_addr("192.0.2.63".parse().unwrap()));
    }

    #[test]
    fn v4_contains_addr_slash32_is_exact() {
        let p = v4("10.10.1.2/32");
        assert!(p.contains_addr("10.10.1.2".parse().unwrap()));
        assert!(!p.contains_addr("10.10.1.3".parse().unwrap()));
        assert!(!p.contains_addr("10.10.1.0".parse().unwrap()));
    }

    #[test]
    fn v4_contains_addr_slash0_matches_everything() {
        // Guards `!0u32 << 32`.
        let p = v4("0.0.0.0/0");
        assert!(p.contains_addr("1.2.3.4".parse().unwrap()));
        assert!(p.contains_addr("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn v4_contains_addr_ignores_declared_host_bits() {
        let p = v4("192.0.2.5/24");
        assert!(p.contains_addr("192.0.2.10".parse().unwrap()));
        assert_eq!(p.network(), "192.0.2.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn v6_contains_addr_basic() {
        let p = v6("2001:db8:0:1337::/64");
        assert!(p.contains_addr("2001:db8:0:1337::1".parse().unwrap()));
        assert!(p.contains_addr("2001:db8:0:1337:dead:beef::42".parse().unwrap()));
        assert!(!p.contains_addr("2001:db8:0:1338::1".parse().unwrap()));
        assert!(!p.contains_addr("2001:db8:1::1".parse().unwrap()));
    }

    #[test]
    fn v6_contains_addr_slash128_is_exact() {
        let p = v6("2001:db8::2/128");
        assert!(p.contains_addr("2001:db8::2".parse().unwrap()));
        assert!(!p.contains_addr("2001:db8::3".parse().unwrap()));
    }

    #[test]
    fn v6_contains_addr_slash0_matches_everything() {
        // Guards `!0u128 << 128`. In release that shift silently yields
        // `!0`, which would make `::/0` match only `::` — a quiet
        // wrong-answer rather than a panic.
        let p = v6("::/0");
        assert!(p.contains_addr("2001:db8::1".parse().unwrap()));
        assert!(p.contains_addr("::".parse().unwrap()));
        assert!(p.contains_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    #[test]
    fn v6_contains_addr_ignores_declared_host_bits() {
        let p = v6("2001:db8:0:1337::5/64");
        assert!(p.contains_addr("2001:db8:0:1337::10".parse().unwrap()));
        assert_eq!(
            p.network(),
            "2001:db8:0:1337::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn contains_prefix_rejects_less_specific_inner() {
        // A /24 does not contain the /16 that covers it.
        assert!(!v4("10.1.0.0/24").contains_prefix(&v4("10.1.0.0/16")));
        assert!(v4("10.1.0.0/16").contains_prefix(&v4("10.1.0.0/24")));
        // Equal prefixes contain each other.
        assert!(v4("10.1.0.0/24").contains_prefix(&v4("10.1.0.0/24")));
        // Disjoint.
        assert!(!v4("10.1.0.0/16").contains_prefix(&v4("10.2.0.0/24")));
    }

    #[test]
    fn contains_prefix_v6() {
        assert!(v6("2001:db8::/48").contains_prefix(&v6("2001:db8:0:1337::/64")));
        assert!(!v6("2001:db8::/48").contains_prefix(&v6("2001:db8:1::/48")));
        assert!(!v6("2001:db8:0:1337::/64").contains_prefix(&v6("2001:db8::/48")));
        assert!(v6("::/0").contains_prefix(&v6("2001:db8::/32")));
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
        let s = "  route-source bgp 127.0.0.1:1179 local-as 65551 peer-as 65551 router-id 198.51.100.7\n";
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
                anyip,
            } => {
                assert_eq!(addr, "127.0.0.1");
                assert_eq!(port, 1179);
                assert_eq!(local_as, 65551);
                assert_eq!(peer_as, 65551);
                assert_eq!(router_id, Some("198.51.100.7".parse().unwrap()));
                assert!(!allow_remote, "loopback default does not need opt-in");
                assert!(peer_from.is_empty());
                assert!(peer_ip.is_none());
                assert!(!anyip, "anyip defaults off");
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
        let e = parse_module_body("  route-source bgp 127.0.0.1:1179 peer-as 65551\n").unwrap_err();
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
    fn route_source_bracketed_ipv4_rejected() {
        let e = parse_module_body("  route-source bgp [192.0.2.202]:1179 local-as 1 peer-as 1\n")
            .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("bracketed IPv4"), "got: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_route_source_rejected() {
        let e = parse_module_body(
            "  route-source bmp 127.0.0.1:6543 require-loc-rib\n  \
             route-source bgp 127.0.0.1:1179 local-as 1 peer-as 1\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(
                    message.contains("duplicate `route-source`"),
                    "got: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_anyip_parses() {
        let s = "  route-source bgp 192.0.2.202:1179 local-as 65551 peer-as 65551 \
                 allow-remote peer-from 192.0.2.201/32 anyip\n";
        match extract_route_source(s) {
            RouteSourceSpec::Bgp {
                addr,
                allow_remote,
                peer_from,
                anyip,
                ..
            } => {
                assert_eq!(addr, "192.0.2.202");
                assert!(allow_remote);
                assert_eq!(peer_from.len(), 1);
                assert!(anyip);
            }
            other => panic!("expected Bgp, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_anyip_without_allow_remote_errors() {
        // `anyip` on a loopback listen is doubly wrong (a loopback
        // address is never a phantom), and the allow-remote
        // requirement is what rejects it.
        let e = parse_module_body("  route-source bgp 127.0.0.1:1179 local-as 1 peer-as 1 anyip\n")
            .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("anyip"), "got: {message}");
                assert!(message.contains("allow-remote"), "got: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn route_source_bgp_anyip_non_unicast_listen_errors() {
        for addr in ["0.0.0.0", "224.0.0.9", "255.255.255.255"] {
            let e = parse_module_body(&format!(
                "  route-source bgp {addr}:1179 local-as 1 peer-as 1 \
                 allow-remote peer-from 10.0.0.1/32 anyip\n"
            ))
            .unwrap_err();
            match e {
                ConfigError::Parse { message, .. } => {
                    assert!(message.contains("unicast"), "addr {addr}: got {message}");
                }
                other => panic!("expected Parse for {addr}, got {other:?}"),
            }
        }
    }

    #[test]
    fn route_source_bgp_anyip_v6_listen_errors() {
        let e = parse_module_body(
            "  route-source bgp [2001:db8::2]:1179 local-as 1 peer-as 1 \
             allow-remote peer-from 2001:db8::1/128 anyip\n",
        )
        .unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("IPv4"), "got: {message}");
            }
            other => panic!("expected Parse, got {other:?}"),
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
        let lp = extract_local_prefixes("  local-prefix 192.0.2.0/24 via br1337\n");
        assert_eq!(lp.len(), 1);
        let (cidr, iface) = &lp[0];
        assert_eq!(cidr.addr, "192.0.2.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cidr.prefix_len, 24);
        assert_eq!(iface, "br1337");
    }

    #[test]
    fn local_prefix_multiple_directives_accumulate() {
        let body = "  local-prefix 192.0.2.0/24 via br1337\n\
                    local-prefix 198.51.100.0/24 via br88\n\
                    local-prefix 10.10.1.0/24 via br0\n";
        let lp = extract_local_prefixes(body);
        assert_eq!(lp.len(), 3);
        let ifaces: Vec<&str> = lp.iter().map(|(_, i)| i.as_str()).collect();
        assert_eq!(ifaces, vec!["br1337", "br88", "br0"]);
    }

    #[test]
    fn local_prefix_missing_via_keyword_errors() {
        let e = parse_module_body("  local-prefix 192.0.2.0/24 br1337\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("expected `via`"), "message was: {message}");
            }
            _ => panic!("expected Parse error, got {e:?}"),
        }
    }

    #[test]
    fn local_prefix_missing_iface_errors() {
        let e = parse_module_body("  local-prefix 192.0.2.0/24 via\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix_missing_cidr_errors() {
        let e = parse_module_body("  local-prefix\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix_extra_arg_errors() {
        let e = parse_module_body("  local-prefix 192.0.2.0/24 via br1337 garbage\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("unknown tail flag"), "msg: {message}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn local_prefix_bad_cidr_errors() {
        let e = parse_module_body("  local-prefix 192.0.2.0 via br1337\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix_arp_scavenge_flag_parses() {
        let m = parse_module_body("  local-prefix 192.0.2.0/24 via br1337 arp-scavenge\n")
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
        let m = parse_module_body("  local-prefix 192.0.2.0/24 via br1337\n").expect("parse");
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
             local-prefix 192.0.2.0/24 via br1337\n  \
             local-prefix 198.51.100.0/24 via br88\n",
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

    // --- local-prefix6 (IPv6 connected fast-path) ------------------------

    fn extract_local_prefixes6(body: &str) -> Vec<(Ipv6Prefix, String)> {
        let m = parse_module_body(body).expect("parse");
        m.directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::LocalPrefix6 { cidr, iface, .. } => Some((*cidr, iface.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn local_prefix6_parses_basic_form() {
        let lp = extract_local_prefixes6("  local-prefix6 2001:db8:0:1337::/64 via br1337\n");
        assert_eq!(lp.len(), 1);
        assert_eq!(
            lp[0].0.addr,
            "2001:db8:0:1337::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(lp[0].0.prefix_len, 64);
        assert_eq!(lp[0].1, "br1337");
    }

    #[test]
    fn local_prefix6_multiple_directives_accumulate() {
        let body = "  local-prefix6 2001:db8:0:1337::/64 via br1337\n\
                    local-prefix6 2001:db8:0:88::/64 via br88\n\
                    local-prefix6 fd00:1::/64 via br0\n";
        let lp = extract_local_prefixes6(body);
        assert_eq!(lp.len(), 3);
        let ifaces: Vec<&str> = lp.iter().map(|(_, i)| i.as_str()).collect();
        assert_eq!(ifaces, ["br1337", "br88", "br0"]);
    }

    #[test]
    fn local_prefix6_unique_local_is_allowed() {
        // fc00::/7 is a legitimate connected segment; only the classes
        // that can never be forwarded are rejected.
        let lp = extract_local_prefixes6("  local-prefix6 fd00:1234::/64 via br0\n");
        assert_eq!(lp.len(), 1);
    }

    #[test]
    fn local_prefix6_and_v4_coexist_without_cross_contamination() {
        let body = "  local-prefix 192.0.2.0/24 via br1337\n\
                    local-prefix6 2001:db8:0:1337::/64 via br1337\n";
        let v4 = extract_local_prefixes(body);
        let v6 = extract_local_prefixes6(body);
        assert_eq!(v4.len(), 1, "v4 extractor must see only the v4 directive");
        assert_eq!(v6.len(), 1, "v6 extractor must see only the v6 directive");
        assert_eq!(v4[0].0.prefix_len, 24);
        assert_eq!(v6[0].0.prefix_len, 64);
    }

    #[test]
    fn local_prefix6_rejects_default_route() {
        // The highest-value rejection: ::/0 would harvest the entire
        // neighbour table, multicast and link-local included.
        let e = parse_module_body("  local-prefix6 ::/0 via br0\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("::/0"), "got: {msg}");
    }

    #[test]
    fn local_prefix6_rejects_multicast_prefix() {
        for cidr in ["ff00::/8", "ff02::/16", "ff02::1/128"] {
            let e = parse_module_body(&format!("  local-prefix6 {cidr} via br0\n")).unwrap_err();
            let msg = format!("{e}");
            assert!(msg.contains("multicast"), "{cidr} -> {msg}");
        }
    }

    #[test]
    fn local_prefix6_rejects_link_local_prefix() {
        for cidr in ["fe80::/10", "fe80::/64", "fe80::1/128"] {
            let e = parse_module_body(&format!("  local-prefix6 {cidr} via br0\n")).unwrap_err();
            let msg = format!("{e}");
            assert!(msg.contains("link-local"), "{cidr} -> {msg}");
        }
    }

    #[test]
    fn local_prefix6_rejects_unspecified_loopback_and_ipv4_mapped() {
        for (cidr, needle) in [
            ("::/128", "unspecified"),
            ("::1/128", "loopback"),
            ("::ffff:0:0/96", "IPv4-mapped"),
        ] {
            let e = parse_module_body(&format!("  local-prefix6 {cidr} via br0\n")).unwrap_err();
            let msg = format!("{e}");
            assert!(msg.contains(needle), "{cidr} -> {msg}");
        }
    }

    #[test]
    fn local_prefix6_rejects_arp_scavenge_with_reason() {
        let e = parse_module_body("  local-prefix6 2001:db8:0:1337::/64 via br0 arp-scavenge\n")
            .unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("IPv4-only"), "got: {msg}");
        assert!(msg.contains("not enumerable"), "got: {msg}");
    }

    #[test]
    fn local_prefix6_missing_via_keyword_errors() {
        let e = parse_module_body("  local-prefix6 2001:db8::/48 br0\n").unwrap_err();
        assert!(format!("{e}").contains("expected `via`"));
    }

    #[test]
    fn local_prefix6_missing_iface_errors() {
        let e = parse_module_body("  local-prefix6 2001:db8::/48 via\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix6_missing_cidr_errors() {
        let e = parse_module_body("  local-prefix6\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    #[test]
    fn local_prefix6_unknown_tail_flag_errors() {
        let e = parse_module_body("  local-prefix6 2001:db8::/48 via br0 garbage\n").unwrap_err();
        assert!(format!("{e}").contains("unknown tail flag"));
    }

    #[test]
    fn local_prefix6_iface_sanitized() {
        let e = parse_module_body("  local-prefix6 2001:db8::/48 via has space\n").unwrap_err();
        assert!(matches!(e, ConfigError::Parse { .. }));
    }

    /// Regression guard for the paired-keyword design. A malformed v6
    /// CIDR must still surface the precise `FromStr` diagnostic; a
    /// try-v4-then-v6 polymorphic parser would collapse both into a
    /// generic "cannot parse as IPv4 or IPv6".
    #[test]
    fn local_prefix6_bad_cidr_surfaces_precise_error() {
        let e = parse_module_body("  local-prefix6 2001:db8::gg/64 via br0\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("bad IPv6"), "got: {msg}");

        let e = parse_module_body("  local-prefix6 2001:db8::/129 via br0\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("0..=128"), "got: {msg}");
    }

    #[test]
    fn local_prefix_family_mismatch_hints_at_other_directive() {
        // v6 CIDR under the v4 keyword.
        let e = parse_module_body("  local-prefix 2001:db8::/48 via br0\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("local-prefix6"), "got: {msg}");

        // v4 CIDR under the v6 keyword.
        let e = parse_module_body("  local-prefix6 192.0.2.0/24 via br0\n").unwrap_err();
        let msg = format!("{e}");
        assert!(msg.contains("did you mean `local-prefix`"), "got: {msg}");
    }

    #[test]
    fn local_prefix6_iface_validated_against_sysfs() {
        let dir = std::env::temp_dir().join(format!(
            "pf-cfg-local-prefix6-{}-{}",
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
             local-prefix6 2001:db8:0:1337::/64 via br1337\n  \
             local-prefix6 2001:db8:0:88::/64 via br88\n",
        )
        .expect("parse ok; validation runs separately");
        let err = cfg.validate_interfaces_in(&dir).unwrap_err();
        match err {
            ConfigError::InterfaceMissing { iface, .. } => assert_eq!(iface, "br88"),
            other => panic!("expected InterfaceMissing, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_harvestable_v6_rejects_non_global_unicast() {
        for a in [
            "ff02::1",
            "ff02::2",
            "ff02::1:ff00:1", // solicited-node
            "ff05::c",
            "fe80::1",
            "fe80::200:5eff:fe00:1",
            "::",
            "::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(
                !is_harvestable_v6(a.parse().unwrap()),
                "{a} must not be harvestable"
            );
        }
        for a in [
            "2001:db8:0:1337::42",
            "2001:db8:0:1337::", // subnet-router anycast: a real address
            "2001:db8::1",
            "fd00:1::1", // unique-local is fine
        ] {
            assert!(
                is_harvestable_v6(a.parse().unwrap()),
                "{a} must be harvestable"
            );
        }
    }

    /// The per-address gate and the parse-time class table must agree,
    /// or a prefix could pass validation and then have every address
    /// inside it filtered at emission (or vice versa).
    #[test]
    fn harvestable_gate_agrees_with_forbidden_class_table() {
        for (class, reason) in FORBIDDEN_V6_CLASSES {
            assert!(
                !is_harvestable_v6(class.addr),
                "{reason}: class network address should be rejected by is_harvestable_v6"
            );
        }
    }

    // --- uncovered_local_prefix_warnings ---------------------------------

    fn warnings_for(body: &str) -> Vec<String> {
        let m = parse_module_body(body).expect("parse");
        uncovered_local_prefix_warnings(&m.directives)
    }

    #[test]
    fn covered_local_prefixes_produce_no_warnings() {
        let w = warnings_for(
            "  allow-prefix 192.0.2.0/24\n\
             allow-prefix6 2001:db8::/48\n\
             local-prefix 192.0.2.0/24 via br1337\n\
             local-prefix6 2001:db8:0:1337::/64 via br1337\n",
        );
        assert!(w.is_empty(), "unexpected warnings: {w:?}");
    }

    /// The exact production slip this exists for: the operator carried
    /// over the v4 pair but declared only half of the v6 pair.
    #[test]
    fn local_prefix6_without_allow_prefix6_warns() {
        let w = warnings_for(
            "  allow-prefix 192.0.2.0/24\n\
             local-prefix 192.0.2.0/24 via br1337\n\
             local-prefix6 2001:db8:0:1337::/64 via br1337\n",
        );
        assert_eq!(w.len(), 1, "got: {w:?}");
        assert!(w[0].contains("local-prefix6"), "got: {}", w[0]);
        assert!(w[0].contains("allow-prefix6"), "got: {}", w[0]);
    }

    #[test]
    fn local_prefix_v4_without_allow_warns() {
        let w = warnings_for("  local-prefix 198.51.100.0/24 via br88\n");
        assert_eq!(w.len(), 1, "got: {w:?}");
        assert!(
            w[0].contains("local-prefix 198.51.100.0/24"),
            "got: {}",
            w[0]
        );
    }

    #[test]
    fn cross_family_allow_does_not_cover() {
        // A v4 allowlist must not silence the v6 warning or vice versa.
        let w = warnings_for(
            "  allow-prefix6 2001:db8::/48\n\
             local-prefix 192.0.2.0/24 via br1337\n",
        );
        assert_eq!(w.len(), 1, "got: {w:?}");
    }

    #[test]
    fn overlap_counts_even_when_allow_is_narrower() {
        // An allow entry narrower than the local prefix still means the
        // operator wired the two together; only zero overlap warns.
        let w = warnings_for(
            "  allow-prefix 192.0.2.128/25\n\
             local-prefix 192.0.2.0/24 via br1337\n",
        );
        assert!(w.is_empty(), "narrower allow overlaps, no warn: {w:?}");
    }

    // --- v0.2.1 fallback-default + block-prefix ---

    #[test]
    fn fallback_default_parses_basic_form() {
        let m = parse_module_body("  fallback-default via eth3 nexthop 198.51.100.50\n")
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
                "198.51.100.50".parse::<Ipv4Addr>().unwrap()
            ))
        );
    }

    #[test]
    fn fallback_default_missing_via_errors() {
        let e = parse_module_body("  fallback-default eth3 nexthop 198.51.100.50\n").unwrap_err();
        match e {
            ConfigError::Parse { message, .. } => {
                assert!(message.contains("expected `via`"), "msg: {message}");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn fallback_default_missing_nexthop_keyword_errors() {
        let e = parse_module_body("  fallback-default via eth3 198.51.100.50\n").unwrap_err();
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
        let m = parse_module_body("  mss-clamp 203.0.113.0/24 1280\n").expect("parse");
        let v = extract_mss_clamps(&m);
        assert_eq!(v.len(), 1);
        match v[0].0.as_ref().unwrap() {
            MssClampPrefix::V4(p) => {
                assert_eq!(p.addr.octets(), [203, 0, 113, 0]);
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
        let m = parse_module_body("  mss-clamp 203.0.113.0/24 via eth2 1280\n").expect("parse");
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
                    mss-clamp 203.0.113.0/24 1280\n";
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

    /// The membership rule must hold for a config arriving by SIGHUP,
    /// not only one arriving at startup.
    ///
    /// This is the shape the rollout actually takes: start with every
    /// port `steer off` (always valid, membership-only), then flip one
    /// port on and reload. If only startup validates, that flip is
    /// unchecked — and it is the exact moment traffic starts being
    /// diverted, with other egress ports possibly having no `port` line
    /// at all.
    ///
    /// Asserted on the *config* rather than through the signal handler
    /// because the handler needs a live daemon; what has to be true is
    /// that the same predicate rejects the same file, whichever door it
    /// comes through.
    #[test]
    fn the_membership_rule_rejects_a_steer_on_reload_too() {
        // The staging state the ladder starts from: two attached ports,
        // both members, neither steering.
        let staged = "module fast-path\n  attach eth4 generic\n  attach eth5 generic\n  \
                      forwarding-mode custom-fib\n\n\
                      module vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth4 cores 1 steer off\n  \
                      port eth5 cores 1 steer off\n  expected-routes 100\n";
        Config::parse(staged)
            .unwrap()
            .validate_vpp_offload()
            .expect("all-steer-off is the designed staging state");

        // The rollout's first rung, with one member quietly missing.
        // Startup would refuse this; so must a reload.
        let rung_one = "module fast-path\n  attach eth4 generic\n  attach eth5 generic\n  \
                        forwarding-mode custom-fib\n\n\
                        module vpp-offload\n  loopback-address 198.51.100.1/32\n  port eth5 cores 1 steer on\n  \
                        expected-routes 100\n";
        let e = Config::parse(rung_one)
            .unwrap()
            .validate_vpp_offload()
            .expect_err("eth4 has no port line while eth5 steers");
        assert!(
            format!("{e}").contains("eth4"),
            "the refusal must name the uncovered port: {e}"
        );
    }

    // --- guard module grammar + validation ---

    /// A full guard section in the documented shape parses, and every
    /// field lands where the parser promised.
    #[test]
    fn guard_section_parses_reference_shape() {
        let s = "module fast-path\n\
                 \x20 attach eth0 generic\n\
                 module guard\n\
                 \x20 interface br3998\n\
                 \x20 interface br3999\n\
                 \x20 arp-ns-ratelimit br3998 rate 3/60s burst 3\n\
                 \x20 lldp br3998 drop\n\
                 \x20 foreign-src br3998 monitor\n\
                 \x20 bcast-mcast-ratelimit br3998 rate 50/1s monitor\n\
                 \x20 arp-ns-ratelimit br3999 rate 2/30s\n";
        let c = Config::parse(s).unwrap();
        c.validate_guard().expect("reference shape must validate");
        let m = &c.modules[1];
        assert_eq!(m.name, "guard");
        match &m.directives[2] {
            ModuleDirective::GuardArpNsRatelimit {
                iface,
                rate,
                per,
                burst,
                monitor,
                ..
            } => {
                assert_eq!(iface, "br3998");
                assert_eq!(*rate, 3);
                assert_eq!(*per, Duration::from_secs(60));
                assert_eq!(*burst, 3);
                assert!(!monitor);
            }
            other => panic!("expected GuardArpNsRatelimit, got {other:?}"),
        }
        match &m.directives[3] {
            ModuleDirective::GuardLldp { iface, monitor, .. } => {
                assert_eq!(iface, "br3998");
                assert!(!monitor);
            }
            other => panic!("expected GuardLldp, got {other:?}"),
        }
        match &m.directives[4] {
            ModuleDirective::GuardForeignSrc { monitor, .. } => assert!(monitor),
            other => panic!("expected GuardForeignSrc, got {other:?}"),
        }
        // burst defaults to the rate count when omitted.
        match &m.directives[6] {
            ModuleDirective::GuardArpNsRatelimit { rate, burst, .. } => {
                assert_eq!(*rate, 2);
                assert_eq!(*burst, 2);
            }
            other => panic!("expected GuardArpNsRatelimit, got {other:?}"),
        }
    }

    #[test]
    fn guard_ratelimit_grammar_refusals() {
        // (body line, expected message fragment)
        let cases = [
            ("arp-ns-ratelimit br0 rate 3-60s", "rate must be <n>/<dur>"),
            ("arp-ns-ratelimit br0 rate 0/60s", "rate count must be >= 1"),
            (
                "arp-ns-ratelimit br0 rate 3/0s",
                "rate interval must be non-zero",
            ),
            ("arp-ns-ratelimit br0 rate 3/60m", "duration must end in"),
            ("arp-ns-ratelimit br0 rate 3/7200s", "3600s or less"),
            (
                "arp-ns-ratelimit br0 rate 3/60s burst 0",
                "burst must be >= 1",
            ),
            (
                "arp-ns-ratelimit br0 rate 3/60s burst 70000",
                "65535 or less",
            ),
            (
                "bcast-mcast-ratelimit br0 rate 2000000/1s",
                "1 frame per microsecond",
            ),
            ("arp-ns-ratelimit br0 rate 3/60s burst 2 extra", "takes:"),
            ("arp-ns-ratelimit br0 burst 2", "takes:"),
            ("lldp br0", "drop|monitor"),
            ("lldp br0 on", "drop|monitor"),
            ("foreign-src br0 drop extra", "drop|monitor"),
        ];
        for (body, want) in cases {
            let s = format!("module guard\n  {body}\n");
            let e = Config::parse(&s).expect_err(body);
            match e {
                ConfigError::Parse { line, message } => {
                    assert_eq!(line, 2, "for `{body}`");
                    assert!(
                        message.contains(want),
                        "for `{body}`: message was `{message}`"
                    );
                }
                other => panic!("expected Parse for `{body}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn guard_validation_refusals() {
        // (config, expected message fragment)
        let cases = [
            (
                "module guard\n".to_string(),
                "declares no `interface` lines",
            ),
            // The directive namespace is shared across module sections,
            // so a guard section holding only another module's
            // directives parses — it must still be refused (PR #204
            // review finding: a raw non-emptiness check waved this
            // through as a silent no-op attach).
            (
                "module guard\n  attach eth0 native\n".to_string(),
                "declares no `interface` lines",
            ),
            (
                "module guard\n  interface br0\n  interface br0\n  lldp br0 drop\n".to_string(),
                "duplicate `interface br0`",
            ),
            (
                "module guard\n  interface br0\n  lldp br0 drop\n  lldp br1 drop\n".to_string(),
                "no `interface br1` line",
            ),
            (
                "module guard\n  interface br0\n  lldp br0 drop\n  lldp br0 monitor\n".to_string(),
                "duplicate `lldp` for br0",
            ),
            (
                "module guard\n  interface br0\n  interface br1\n  lldp br0 drop\n".to_string(),
                "`interface br1` declares no rules",
            ),
            // A fully valid guard section without a fast-path section:
            // v1 rides the fast-path daemon (the startup capability
            // gate assumes it), so guard-only is refused explicitly
            // rather than several confusing steps downstream (review
            // finding, PR #206).
            (
                "module guard\n  interface br0\n  lldp br0 drop\n".to_string(),
                "requires a `module fast-path` section",
            ),
        ];
        for (s, want) in cases {
            let e = Config::parse(&s).unwrap().validate_guard().expect_err(&s);
            assert!(
                format!("{e}").contains(want),
                "for config `{s}`: error was `{e}`"
            );
        }
    }

    /// The interface count is capped at the BPF config map's capacity
    /// — a 65th interface must be refused before any filter attaches,
    /// not fail mid-attach with 64 filters live.
    #[test]
    fn guard_interface_count_is_capped_at_the_map_size() {
        let over = |n: usize| {
            let mut s = String::from("module fast-path\n  attach eth0 generic\nmodule guard\n");
            for i in 0..n {
                s.push_str(&format!("  interface br{i}\n  lldp br{i} drop\n"));
            }
            s
        };
        let e = Config::parse(&over(GUARD_MAX_INTERFACES + 1))
            .unwrap()
            .validate_guard()
            .expect_err("65 interfaces refused");
        assert!(
            format!("{e}").contains(&format!("exceed the {GUARD_MAX_INTERFACES}")),
            "{e}"
        );
        Config::parse(&over(GUARD_MAX_INTERFACES))
            .unwrap()
            .validate_guard()
            .expect("exactly the cap is allowed");
    }

    /// Guard interfaces join the sysfs existence check exactly like
    /// fast-path `attach` interfaces.
    #[test]
    fn guard_interfaces_are_sysfs_checked() {
        let dir = tempfile_shim::TempDir::new("guard-sysfs");
        std::fs::create_dir(dir.path.join("br0")).unwrap();
        let c = Config::parse(
            "module guard\n  interface br0\n  interface br1\n  lldp br0 drop\n  lldp br1 drop\n",
        )
        .unwrap();
        let e = c
            .validate_interfaces_in(&dir.path)
            .expect_err("br1 does not exist");
        match e {
            ConfigError::InterfaceMissing { iface, .. } => assert_eq!(iface, "br1"),
            other => panic!("expected InterfaceMissing, got {other:?}"),
        }
        std::fs::create_dir(dir.path.join("br1")).unwrap();
        c.validate_interfaces_in(&dir.path)
            .expect("both interfaces exist now");
    }

    // --- neigh-snoop module grammar + validation ---

    /// The full documented section shape (placeholder addresses).
    const SNOOP_REFERENCE: &str = "module fast-path\n\
         \x20 attach eth0 generic\n\
         module neigh-snoop\n\
         \x20 bridge br0 ix-mode\n\
         \x20 bridge br1\n\
         \x20 prefix br0 192.0.2.0/24\n\
         \x20 prefix br0 2001:db8:1::/64\n\
         \x20 prefix br0 fe80::/10\n\
         \x20 prefix br1 198.51.100.7/24\n\
         \x20 deny-mac 02:00:00:00:00:01\n\
         \x20 deny-mac 02:00:00:00:00:02\n\
         \x20 peer br0 192.0.2.10 2001:db8:1::10 route-server\n\
         \x20 peer br0 192.0.2.11\n\
         \x20 peer br1 198.51.100.20\n\
         \x20 persist-dir /var/lib/packetframe/state/neigh-cache\n\
         \x20 seed-max-age 14d\n\
         \x20 install-rate 50/1s\n\
         \x20 table-max 4096\n\
         \x20 coverage-interval 60s\n\
         \x20 frr-gate v4 IX-RESOLVED-NH v6 IX-RESOLVED-NH6 interval 30s remove-after 180s\n\
         \x20 rs-coverage-interval 300s\n";

    #[test]
    fn neigh_snoop_section_parses_reference_shape() {
        let c = Config::parse(SNOOP_REFERENCE).unwrap();
        c.validate_neigh_snoop()
            .expect("reference shape must validate");
        let m = &c.modules[1];
        assert_eq!(m.name, "neigh-snoop");
        match &m.directives[0] {
            ModuleDirective::SnoopBridge { iface, ix_mode, .. } => {
                assert_eq!(iface, "br0");
                assert!(ix_mode);
            }
            other => panic!("expected SnoopBridge, got {other:?}"),
        }
        match &m.directives[1] {
            ModuleDirective::SnoopBridge { ix_mode, .. } => assert!(!ix_mode),
            other => panic!("expected SnoopBridge, got {other:?}"),
        }
        // Host bits are cleared, as for allow-prefix.
        match &m.directives[5] {
            ModuleDirective::SnoopPrefix { iface, cidr, .. } => {
                assert_eq!(iface, "br1");
                assert_eq!(cidr.to_string(), "198.51.100.0/24");
            }
            other => panic!("expected SnoopPrefix, got {other:?}"),
        }
        match &m.directives[6] {
            ModuleDirective::SnoopDenyMac { mac, .. } => {
                assert_eq!(*mac, [0x02, 0, 0, 0, 0, 0x01]);
            }
            other => panic!("expected SnoopDenyMac, got {other:?}"),
        }
        match &m.directives[8] {
            ModuleDirective::SnoopPeer {
                iface,
                addrs,
                route_server,
                ..
            } => {
                assert_eq!(iface, "br0");
                assert_eq!(addrs.len(), 2);
                assert!(route_server);
            }
            other => panic!("expected SnoopPeer, got {other:?}"),
        }
        match &m.directives[9] {
            ModuleDirective::SnoopPeer { route_server, .. } => assert!(!route_server),
            other => panic!("expected SnoopPeer, got {other:?}"),
        }
        match &m.directives[12] {
            ModuleDirective::SnoopSeedMaxAge { max_age, .. } => {
                assert_eq!(*max_age, Duration::from_secs(14 * 86_400));
            }
            other => panic!("expected SnoopSeedMaxAge, got {other:?}"),
        }
        match &m.directives[13] {
            ModuleDirective::SnoopInstallRate { rate, per, .. } => {
                assert_eq!(*rate, 50);
                assert_eq!(*per, Duration::from_secs(1));
            }
            other => panic!("expected SnoopInstallRate, got {other:?}"),
        }
        match &m.directives[16] {
            ModuleDirective::SnoopFrrGate {
                v4_list,
                v6_list,
                interval,
                remove_after,
                ..
            } => {
                assert_eq!(v4_list, "IX-RESOLVED-NH");
                assert_eq!(v6_list, "IX-RESOLVED-NH6");
                assert_eq!(*interval, Duration::from_secs(30));
                assert_eq!(*remove_after, Duration::from_secs(180));
            }
            other => panic!("expected SnoopFrrGate, got {other:?}"),
        }
    }

    /// `frr-gate` without the optional tail takes the shared defaults.
    #[test]
    fn neigh_snoop_frr_gate_defaults() {
        let c = Config::parse("module neigh-snoop\n  frr-gate v4 A v6 B\n").unwrap();
        match &c.modules[0].directives[0] {
            ModuleDirective::SnoopFrrGate {
                interval,
                remove_after,
                ..
            } => {
                assert_eq!(*interval, NEIGH_SNOOP_DEFAULT_GATE_INTERVAL);
                assert_eq!(*remove_after, NEIGH_SNOOP_DEFAULT_GATE_REMOVE_AFTER);
            }
            other => panic!("expected SnoopFrrGate, got {other:?}"),
        }
    }

    #[test]
    fn neigh_snoop_grammar_refusals() {
        // (body line, expected message fragment)
        let cases = [
            ("bridge", "requires an interface"),
            ("bridge br0 nonsense", "bridge takes:"),
            ("bridge br0 ix-mode extra", "bridge takes:"),
            ("prefix br0", "prefix takes:"),
            ("prefix br0 0.0.0.0/0", "is a /0"),
            ("prefix br0 ::/0", "is a /0"),
            ("prefix br0 192.0.2.0", "bad CIDR"),
            ("prefix br0 192.0.2.0/24 extra", "prefix takes:"),
            ("deny-mac 02:00:00:00:00", "six colon-separated"),
            ("deny-mac 02:00:00:00:00:zz", "is not hex"),
            ("deny-mac 00:00:00:00:00:00", "all-zero"),
            ("deny-mac 01:00:5e:00:00:01", "group bit"),
            ("deny-mac ff:ff:ff:ff:ff:ff", "group bit"),
            ("peer br0", "peer takes:"),
            ("peer br0 route-server", "peer takes:"),
            ("peer br0 192.0.2.1 route-server 192.0.2.2", "peer takes:"),
            ("peer br0 192.0.2.1 192.0.2.1", "listed twice"),
            ("peer br0 0.0.0.0", "cannot be a neighbour"),
            ("peer br0 224.0.0.1", "cannot be a neighbour"),
            ("peer br0 ::1", "cannot be a neighbour"),
            ("peer br0 not-an-ip", "is not an IP address"),
            ("persist-dir relative/path", "must be absolute"),
            ("persist-dir /a/../b", ".."),
            ("seed-max-age 14", "whole number of days"),
            ("seed-max-age 0d", "between 1d and 365d"),
            ("seed-max-age 400d", "between 1d and 365d"),
            ("install-rate 50", "install-rate takes:"),
            ("install-rate 0/1s", "count must be >= 1"),
            ("install-rate 50/0s", "interval must be non-zero"),
            ("install-rate 1/7200s", "3600s or less"),
            ("install-rate 5000/1s", "netlink storm"),
            ("install-rate 50/1s extra", "install-rate takes:"),
            ("table-max 1", "between 16 and 1048576"),
            ("table-max 2000000", "between 16 and 1048576"),
            ("table-max lots", "bad integer"),
            ("coverage-interval 1s", "between 5s and 3600s"),
            ("coverage-interval 5000s", "between 5s and 3600s"),
            ("coverage-interval 5m", "duration must end in"),
            ("frr-gate A v6 B", "expected `v4`"),
            ("frr-gate v4 A B", "expected `v6`"),
            ("frr-gate v4 A v6 A", "different names"),
            ("frr-gate v4 A/B v6 C", "is not a prefix-list name"),
            ("frr-gate v4 A v6 B interval 1s", "between 5s and 600s"),
            (
                "frr-gate v4 A v6 B remove-after 9999s",
                "between 0s and 3600s",
            ),
            ("frr-gate v4 A v6 B interval", "frr-gate takes:"),
            (
                "frr-gate v4 A v6 B interval 30s interval 30s",
                "frr-gate takes:",
            ),
            ("frr-gate v4 A v6 B bogus 1s", "frr-gate takes:"),
            ("rs-coverage-interval 1s", "between 5s and 3600s"),
        ];
        for (body, want) in cases {
            let s = format!("module neigh-snoop\n  {body}\n");
            let e = Config::parse(&s).expect_err(body);
            match e {
                ConfigError::Parse { line, message } => {
                    assert_eq!(line, 2, "for `{body}`");
                    assert!(
                        message.contains(want),
                        "for `{body}`: message was `{message}`"
                    );
                }
                other => panic!("expected Parse for `{body}`, got {other:?}"),
            }
        }
    }

    /// Every rule in `validate_neigh_snoop`, one case each. Each body
    /// is a complete, otherwise-valid section so exactly one rule can
    /// be the refusal.
    #[test]
    fn neigh_snoop_validation_refusals() {
        let fp = "module fast-path\n  attach eth0 generic\n";
        let ok_bridge = "  bridge br0\n  prefix br0 192.0.2.0/24\n";
        let cases: Vec<(String, &str)> = vec![
            (
                format!("{fp}module neigh-snoop\n  attach eth1 generic\n"),
                "declares no `bridge` lines",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  bridge br0\n"),
                "duplicate `bridge br0`",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  prefix br9 192.0.2.0/24\n"),
                "no `bridge br9` line",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  peer br9 192.0.2.5\n"),
                "no `bridge br9` line",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  bridge br1\n"),
                "`bridge br1` has no `prefix` lines",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  prefix br0 192.0.2.0/24\n"),
                "duplicate `prefix br0 192.0.2.0/24`",
            ),
            (
                format!(
                    "{fp}module neigh-snoop\n{ok_bridge}  deny-mac 02:00:00:00:00:01\n  \
                     deny-mac 02:00:00:00:00:01\n"
                ),
                "duplicate `deny-mac 02:00:00:00:00:01`",
            ),
            (
                format!(
                    "{fp}module neigh-snoop\n{ok_bridge}  peer br0 192.0.2.5\n  \
                     peer br0 192.0.2.5\n"
                ),
                "appears twice",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  peer br0 198.51.100.5\n"),
                "outside every `prefix`",
            ),
            (
                format!(
                    "{fp}module neigh-snoop\n{ok_bridge}  table-max 16\n{}",
                    (1..=17)
                        .map(|i| format!("  peer br0 192.0.2.{i}\n"))
                        .collect::<String>()
                ),
                "exceed `table-max 16`",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  table-max 16\n  table-max 32\n"),
                "`table-max` may appear once",
            ),
            (
                format!(
                    "{fp}module neigh-snoop\n{ok_bridge}  persist-dir /var/lib/packetframe/state\n"
                ),
                "is the global state-dir",
            ),
            (
                format!("{fp}module neigh-snoop\n{ok_bridge}  peer br0 192.0.2.5 route-server\n"),
                "requires `frr-gate`",
            ),
            (
                format!("module neigh-snoop\n{ok_bridge}"),
                "requires a `module fast-path` section",
            ),
        ];
        for (s, want) in cases {
            let c = Config::parse(&s).unwrap_or_else(|e| panic!("parse of\n{s}\nfailed: {e}"));
            let e = c
                .validate_neigh_snoop()
                .expect_err(&format!("expected refusal `{want}` for\n{s}"));
            assert!(e.to_string().contains(want), "for\n{s}\nmessage was `{e}`");
        }
        // And the bridge cap, generated.
        let mut s = format!("{fp}module neigh-snoop\n");
        for i in 0..=NEIGH_SNOOP_MAX_BRIDGES {
            s.push_str(&format!("  bridge b{i}\n  prefix b{i} 192.0.2.0/24\n"));
        }
        let e = Config::parse(&s)
            .unwrap()
            .validate_neigh_snoop()
            .expect_err("one over the cap");
        assert!(e.to_string().contains("exceed the 16"), "{e}");
    }

    /// A guard `interface br0` and a snooper `bridge br0` coexist in
    /// one config: the directive heads differ, and each validator sees
    /// only its own section.
    #[test]
    fn neigh_snoop_and_guard_do_not_collide() {
        let s = "module fast-path\n  attach eth0 generic\n\
                 module guard\n  interface br0\n  lldp br0 drop\n\
                 module neigh-snoop\n  bridge br0\n  prefix br0 192.0.2.0/24\n";
        let c = Config::parse(s).unwrap();
        c.validate_guard().unwrap();
        c.validate_neigh_snoop().unwrap();
        // A guard section with a snooper directive in it is refused by
        // the guard validator (no `interface` line), never accepted as
        // a bridge.
        let s = "module fast-path\n  attach eth0 generic\nmodule guard\n  bridge br0\n";
        let e = Config::parse(s)
            .unwrap()
            .validate_guard()
            .expect_err("foreign head");
        assert!(e.to_string().contains("no `interface` lines"), "{e}");
    }

    #[test]
    fn mac_literal_round_trip() {
        let mac = parse_mac_literal("02:AB:cd:00:ff:10").unwrap();
        assert_eq!(mac, [0x02, 0xab, 0xcd, 0x00, 0xff, 0x10]);
        assert_eq!(format_mac(mac), "02:ab:cd:00:ff:10");
        assert!(parse_mac_literal("02:ab:cd:00:ff").is_err());
        assert!(parse_mac_literal("2:ab:cd:00:ff:10").is_err());
        assert!(parse_mac_literal("02-ab-cd-00-ff-10").is_err());
    }
}
