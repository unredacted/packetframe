//! The exemption tripwire: kernel paths VPP cannot take, unexempted.
//!
//! VPP owns member VFs and the dot1q subinterfaces on them, and
//! nothing else. Any destination the kernel forwards through some
//! OTHER device — an IPSec VTI, WireGuard, a GRE tunnel — has no path
//! in VPP: the mirror route resolves to no member and never installs,
//! so a steered packet for it dies at VPP's default route instead of
//! falling back to the kernel that would have delivered it.
//!
//! The eBPF tier PASSes those flows to the kernel, which is why they
//! work unsteered; steering removes that safety net, and VPP cannot
//! do IPSec, so the kernel path is their permanent, correct home. One
//! `steer-exempt` per such destination keeps them there.
//!
//! Found the hard way on the reference primary (w26, 2026-08-16):
//! inter-site IPSec carried a remote /24 plus seven host routes INSIDE
//! the local service /24, and every steered window for three weeks had
//! been silently one-way-blackholing them — invisible to every
//! watchdog, visible only as a steady rate on a drop counter nobody
//! had decomposed.
//!
//! ## Why a tripwire and not automatic exemption
//!
//! Deriving MCAM rules from kernel state would change forwarding
//! without an operator asking, and could exhaust a 16-slot budget
//! silently. The route sets that produce this are also frequently
//! dynamic — bird announces a new remote host route and the hole
//! re-opens — which is exactly the argument for CONTINUOUS detection
//! rather than a one-time audit. So this names what is uncovered and
//! degrades health; installing the rule stays the operator's decision.

use packetframe_common::config::Ipv4Prefix;

/// One kernel route, reduced to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRoute {
    /// Destination prefix. A default route is `0.0.0.0/0`.
    pub prefix: Ipv4Prefix,
    /// Output device name(s). More than one for a multipath route —
    /// ECMP encodes its nexthops in `RTA_MULTIPATH` rather than
    /// `RTA_OIF`, and a route read as having no device at all would
    /// be skipped silently (review finding). Empty means the kernel
    /// named no interface, which this check has nothing to say about.
    pub oifs: Vec<String>,
    /// Routing table id, for the operator-facing message: "table 100"
    /// is how they will find it again.
    pub table: u32,
    /// Whether the kernel would DROP this itself (blackhole,
    /// unreachable, prohibit). VPP dropping the same packet is
    /// equivalent behaviour, so these are not findings.
    pub drops: bool,
    /// The kernel DELIVERS this itself rather than forwarding over a
    /// path — `RTN_LOCAL` (its own addresses), `RTN_BROADCAST` (the
    /// segment's directed broadcast, `.255` on a service bridge) and
    /// `RTN_ANYCAST`. The `oif` names the interface that owns the
    /// address or segment, which is not an egress VPP could take, so
    /// device reachability says nothing about these and must not be
    /// consulted — the local class this scan exists to cover was
    /// being skipped precisely because those addresses sit on member
    /// ports and bridges, and directed broadcast was being skipped
    /// the same way one round later (both review findings). VPP has
    /// no local delivery and cannot reproduce a broadcast, so
    /// steered traffic to any of them dies unless exempted.
    pub kernel_delivers: bool,
    /// The route names a NEXTHOP OBJECT (`ip route ... nhid N`,
    /// `RTA_NH_ID`) instead of carrying its devices inline. Those
    /// routes are opaque here: the vendored netlink crate does not
    /// parse the attribute, and resolving it means a second
    /// `RTM_GETNEXTHOP` dump this module does not have. Left as a
    /// device-less route it would be SKIPPED — a tunnel-backed nhid
    /// route blackholing under a clean scan (review finding) — so it
    /// is counted and reported as a gap in the scan's own coverage
    /// rather than silently dropped or guessed at.
    pub via_nexthop_object: bool,
    /// The route carries a LIGHTWEIGHT ENCAPSULATION action —
    /// `ip route ... encap mpls|seg6|ip|xfrm ... dev eth3` — named
    /// here by its kernel type for the operator-facing message.
    ///
    /// This one is nastier than a tunnel device, because the `oif` is
    /// an ORDINARY device: a member port, usually. Read for
    /// reachability alone the route looks perfectly coverable, so the
    /// scan would call it clean while the mirror — which encodes
    /// prefix, nexthop and interface, and has nowhere to put a label
    /// stack or a segment list — forwarded the packet bare out the
    /// same port. Bare is not a slower path, it is a different
    /// destination (review finding). The encapsulation is a property
    /// of the PATH, so a multipath hop carrying one counts too.
    pub encap: Option<String>,
}

/// What VPP can actually egress, from config: member ports and the
/// kernel bridge devices `local-route` delivers into.
#[derive(Debug, Clone, Default)]
pub struct VppReach {
    /// `port` lines — VPP owns a VF on each.
    pub members: Vec<String>,
    /// Bridge devices named (indirectly) by `local-route`: VPP
    /// delivers those prefixes on a subif, so a kernel route out the
    /// bridge is covered.
    pub local_devices: Vec<String>,
}

impl VppReach {
    fn covers_device(&self, dev: &str) -> bool {
        self.members.iter().any(|m| m == dev) || self.local_devices.iter().any(|d| d == dev)
    }
}

/// Which destinations steering can actually divert into VPP.
///
/// `Any` — some port matches on SOURCE, so a steered host's packet
/// reaches VPP whatever it is addressed to, and every kernel path is
/// at risk. `OnlyDst(prefixes)` — every steering port matches on
/// destination, so only packets addressed inside the allowlist are
/// diverted at all, and demanding an MCAM slot for a path no packet
/// can reach would spend a scarce resource on nothing (review
/// finding).
#[derive(Debug, Clone)]
pub enum Divertible<'a> {
    Any,
    OnlyDst(&'a [packetframe_common::fib::IpPrefix]),
}

impl Scope<'_> {
    /// Is every DIVERTIBLE packet for this route already exempted?
    ///
    /// Under `Any`, that is every address in the route, so the
    /// exemption must contain the whole prefix. Under `OnlyDst` only
    /// the route's intersection with the allowlist can be diverted at
    /// all — an allowlisted `/32` inside a tunnel-backed `/24` puts
    /// exactly one host at risk — so a `/32` exemption covering that
    /// host covers the risk, and demanding one for the whole `/24`
    /// would send the operator to install a broader rule than the
    /// hazard warrants (review finding).
    ///
    /// Cover is tested against single exemptions, never their union: a
    /// pair of `/25`s covering a `/24` between them still reports. That
    /// under-approximates coverage, which over-reports, which is the
    /// direction this scan is allowed to be wrong in.
    fn covers(&self, route: &Ipv4Prefix) -> bool {
        let covered = |p: &Ipv4Prefix| self.exempts.iter().any(|e| e.contains_prefix(p));
        match &self.divertible {
            Divertible::Any => covered(route),
            Divertible::OnlyDst(allow) => allow
                .iter()
                .filter_map(|a| {
                    let packetframe_common::fib::IpPrefix::V4 { addr, prefix_len } = a else {
                        return None;
                    };
                    let a = Ipv4Prefix {
                        addr: std::net::Ipv4Addr::from(*addr),
                        prefix_len: *prefix_len,
                    };
                    // Two CIDRs that overlap are nested, so the
                    // intersection is whichever is more specific.
                    if a.contains_prefix(route) {
                        Some(*route)
                    } else if route.contains_prefix(&a) {
                        Some(a)
                    } else {
                        None
                    }
                })
                .all(|intersection| covered(&intersection)),
        }
    }
}

impl Divertible<'_> {
    /// Can a packet for `prefix` be diverted into VPP at all?
    ///
    /// OVERLAP, not containment: a dst rule for one address inside a
    /// route's prefix is enough to send traffic for that route into
    /// VPP, so the route is at risk even though the allowlist does
    /// not cover all of it.
    fn reaches(&self, prefix: &Ipv4Prefix) -> bool {
        match self {
            Self::Any => true,
            Self::OnlyDst(allow) => allow.iter().any(|a| {
                let packetframe_common::fib::IpPrefix::V4 { addr, prefix_len } = a else {
                    return false;
                };
                let a = Ipv4Prefix {
                    addr: std::net::Ipv4Addr::from(*addr),
                    prefix_len: *prefix_len,
                };
                a.contains_prefix(prefix) || prefix.contains_prefix(&a)
            }),
        }
    }
}

/// Derive the diversion scope from config — the ONE place it is
/// computed, called at attach and again on every accepted
/// reconfigure.
///
/// A function rather than a value each caller builds, because the
/// inputs are hot: the allowlist and both direction knobs are rebuilt
/// on reconfigure, and a scope captured at attach goes stale the
/// moment either changes — a dst-only deployment that adds an
/// allow-prefix, or flips a port to `src`, starts diverting traffic
/// the frozen scope tells the scan to ignore (review finding, and the
/// same freeze the exemption set had one field over).
///
/// `None` = every destination is at risk: some port matches on
/// source, or nothing steers yet, or the config declares no ports.
/// The conservative answer is the default in all three.
pub fn divertible_scope(
    ports: &[crate::PortLine],
    global: packetframe_common::config::VppSteerDirection,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Option<Vec<packetframe_common::fib::IpPrefix>> {
    use packetframe_common::config::VppSteerDirection;
    if ports.is_empty() {
        return None;
    }
    ports
        .iter()
        .all(|(_, _, _, _, dir)| dir.unwrap_or(global) == VppSteerDirection::Dst)
        .then(|| allowlist.to_vec())
}

/// Everything the comparison judges against, bundled so the parameter
/// list stops growing by one per question asked.
pub struct Scope<'a> {
    pub reach: &'a VppReach,
    pub exempts: &'a [Ipv4Prefix],
    pub divertible: Divertible<'a>,
    /// Tables some policy rule can select. `None` = the rule set could
    /// not be read, so nothing is filtered.
    ///
    /// This models table SELECTION only, never the finer predicates —
    /// fwmark, iif, from/to — deliberately. "A table no rule names
    /// cannot be consulted by any packet" is unconditionally true, so
    /// filtering on it cannot hide a real path; evaluating the rest
    /// would mean reimplementing the kernel's rule walk, where a
    /// permissive mistake re-opens exactly the hole this scan closes.
    /// Over-reporting is the safe direction, and this takes only the
    /// share of it that is provably noise (an unreferenced VRF or
    /// auxiliary table — review finding).
    pub selected_tables: Option<&'a [u32]>,
}

/// A kernel path VPP cannot take that nothing exempts — or, for
/// [`Uncovered::Opaque`], a count of routes this scan could not judge
/// at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uncovered {
    Path {
        prefix: Ipv4Prefix,
        oif: String,
        table: u32,
        /// A terminated address rather than a forwarding path — the
        /// message says so, because the remedy reads differently.
        /// Kernel-owned delivery (an address or a broadcast) rather
        /// than a forwarding path — the message says so, because the
        /// remedy reads differently.
        kernel_delivers: bool,
        /// The lightweight-encapsulation type this path applies, when
        /// it applies one. Present means the finding is about what
        /// the kernel puts ON the packet, not where it sends it, so
        /// the message must not read "via a device VPP does not own"
        /// — VPP very likely owns it, which is the trap.
        encap: Option<String>,
    },
    /// Routes using nexthop objects, whose devices this scan cannot
    /// see. Reported so the operator knows the coverage is partial
    /// rather than believing a quiet scan means a clean box.
    Opaque(usize),
}

impl Uncovered {
    /// How many kernel routes this finding stands for — one, except
    /// for the coverage-gap summary, which stands for as many as it
    /// counted.
    pub fn routes(&self) -> usize {
        match self {
            Self::Path { .. } => 1,
            Self::Opaque(n) => *n,
        }
    }

    /// The table this finding sits in, for tests and log context.
    /// `None` for the coverage-gap summary, which names no route.
    pub fn table(&self) -> Option<u32> {
        match self {
            Self::Path { table, .. } => Some(*table),
            Self::Opaque(_) => None,
        }
    }
}

impl std::fmt::Display for Uncovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Encapsulation first: it is true of a path whatever the
            // route type, and its remedy is the one an operator would
            // never reach from a reachability message.
            Self::Path {
                prefix,
                oif,
                table,
                encap: Some(kind),
                ..
            } => write!(
                f,
                "{}/{} via {oif} (table {table}) applies {kind} encapsulation — VPP's mirror \
                 carries no encap action, so steered packets would leave {oif} bare",
                prefix.addr, prefix.prefix_len
            ),
            Self::Path {
                prefix,
                oif,
                table,
                kernel_delivers: true,
                ..
            } => write!(
                f,
                "{}/{} is delivered by the kernel on {oif} (table {table}) — an address or \
                 broadcast VPP cannot reproduce",
                prefix.addr, prefix.prefix_len
            ),
            Self::Path {
                prefix,
                oif,
                table,
                kernel_delivers: false,
                ..
            } => write!(
                f,
                "{}/{} via {oif} (table {table})",
                prefix.addr, prefix.prefix_len
            ),
            Self::Opaque(n) => write!(
                f,
                "{n} route(s) use nexthop objects (`ip route ... nhid`) whose devices this \
                 scan cannot read, so it cannot tell whether VPP can take them — inspect \
                 with `ip nexthop show` and exempt any that leave via a tunnel"
            ),
        }
    }
}

/// The pure half: which kernel routes would blackhole under steering.
///
/// A route is a finding iff steering can divert traffic for it, the
/// kernel does not drop it itself, VPP has no way to deliver it, and
/// no `steer-exempt` covers its prefix.
///
/// "No way to deliver it" is two different questions:
///
/// - a FORWARDED route is unreachable when none of its nexthop
///   devices is a member port or a `local-route` bridge. Multipath
///   counts as reachable if ANY path is, because VPP installs the
///   paths it can resolve and forwards over those;
/// - a LOCAL route is an address the kernel terminates. VPP has no
///   local delivery at all, so device reachability is irrelevant and
///   asking it is the bug this arm exists to fix — the w23 blackhole
///   was traffic to a gateway address sitting on a bridge that this
///   scan would otherwise have called covered.
///
/// Coverage is by prefix containment, and an exempt must contain the
/// route — not merely overlap it. A `/32` exemption does not cover the
/// `/24` around it, and reporting the `/24` as handled because one
/// host inside it is exempted would be the silent-hole shape all over
/// again.
pub fn uncovered_paths(routes: &[KernelRoute], scope: &Scope<'_>) -> Vec<Uncovered> {
    let reach = scope.reach;
    let mut out = Vec::new();
    // Routes whose devices this scan cannot see at all. Counted
    // across the whole dump and reported once, because the answer is
    // "this scan does not cover N of your routes", not N separate
    // hazards — and flooding a finding per route would make an
    // nhid-using box's tripwire unreadable, which is how an alarm
    // stops being read.
    let mut opaque = 0usize;
    for r in routes {
        if r.drops || !scope.divertible.reaches(&r.prefix) {
            continue;
        }
        // A table no policy rule names is inert for every packet.
        // BEFORE the opaque branch below, not after: an nhid route
        // parked in an unreferenced VRF is no more reachable than a
        // readable one, and counting it would send the operator to
        // inspect nexthops for traffic that cannot exist (review
        // finding — this filter, bypassed by a branch added two
        // rounds after it).
        if scope.selected_tables.is_some_and(|t| !t.contains(&r.table)) {
            continue;
        }
        if r.via_nexthop_object && r.oifs.is_empty() {
            if !scope.covers(&r.prefix) {
                opaque += 1;
            }
            continue;
        }
        let Some(oif) = r.oifs.first() else { continue };
        // A lightweight-encap path is unreproducible REGARDLESS of
        // which device it leaves by, so both reachability arms below
        // are skipped for it — they would clear the route on the
        // strength of an `oif` that is not the problem.
        if r.encap.is_none() {
            if r.kernel_delivers {
                // Only the segments whose hosts steering diverts. A
                // transit port's own address is reachable from a
                // steered host only by a route that would itself be a
                // finding, and reporting every address on the box
                // would demand more exemptions than the 16-slot
                // budget holds — an alarm with no available remedy is
                // one operators learn to ignore. Documented in the
                // runbook, with the null-drop gauge as the backstop
                // for the rest.
                if !reach.local_devices.iter().any(|d| d == oif) {
                    continue;
                }
            } else if r.oifs.iter().any(|d| reach.covers_device(d)) {
                continue;
            }
        }
        // Built-in exemptions cover these on every steered port.
        if crate::steer::BUILTIN_EXEMPTS.iter().any(|(addr, len)| {
            Ipv4Prefix {
                addr: *addr,
                prefix_len: *len,
            }
            .contains_prefix(&r.prefix)
        }) {
            continue;
        }
        if scope.covers(&r.prefix) {
            continue;
        }
        out.push(Uncovered::Path {
            prefix: r.prefix,
            oif: oif.clone(),
            table: r.table,
            kernel_delivers: r.kernel_delivers,
            encap: r.encap.clone(),
        });
    }
    out.sort_by_key(|u| match u {
        Uncovered::Path { prefix, .. } => (prefix.prefix_len, u32::from(prefix.addr)),
        Uncovered::Opaque(_) => (u8::MAX, u32::MAX),
    });
    out.dedup();
    if opaque > 0 {
        out.push(Uncovered::Opaque(opaque));
    }
    out
}

/// The scan seam the runtime holds, mirroring [`crate::fdb::FdbWatch`]:
/// a trait so tests record calls and non-Linux builds never pretend.
/// What one scan concluded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriftFindings {
    /// One line per finding, for the health surface.
    pub lines: Vec<String>,
    /// How many ROUTES those lines represent. Not `lines.len()`: the
    /// nexthop-object summary is one line for `n` routes, and a gauge
    /// derived from the line count published `1` however much of the
    /// table the scan could not see — undercounting exactly the blind
    /// portion it exists to report (review finding).
    pub routes: usize,
}

pub trait DriftWatch {
    /// The scan's findings, empty when the exemptions hold. `Err` =
    /// the kernel would not answer; the caller keeps its previous
    /// verdict.
    fn uncovered(&mut self) -> Result<DriftFindings, String>;

    /// Adopt a reloaded exemption set AND diversion scope. Called
    /// from the same place the steering target is retargeted, so the
    /// scan judges the config the operator just applied rather than
    /// the one at attach. Both travel together because both come from
    /// the same reconfigure and freezing either one re-opens the hole.
    fn set_scope(
        &mut self,
        exempts: Vec<Ipv4Prefix>,
        dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
    );
}

/// The exemptions and diversion scope a scan judges against, as the
/// loop hands them over.
pub type ScopeUpdate = (
    Vec<Ipv4Prefix>,
    Option<Vec<packetframe_common::fib::IpPrefix>>,
);

/// A completed pass and the scope generation it judged under.
type StampedResult = (u64, Result<DriftFindings, String>);

#[derive(Default)]
struct ScannerInbox {
    /// A scope waiting to be adopted. Only the newest matters — an
    /// older pending scope is superseded, not queued.
    pending: Option<ScopeUpdate>,
    /// Which scope the pending (or last adopted) one IS. Lives HERE,
    /// under the same lock as `pending`, because the two must move
    /// together: an atomic bumped outside the lock let the worker
    /// adopt nothing, read the incremented counter, and stamp a scan
    /// of the OLD exemptions as belonging to the NEW scope — the
    /// stale-result check would then accept it as current and publish
    /// a clean verdict over a path the new config had just stopped
    /// exempting (review finding). One lock, one truth.
    generation: u64,
    stop: bool,
}

/// The scan, running on its OWN thread.
///
/// A full `RTM_GETROUTE` dump on the reference primary walks ~1.05M
/// prefixes — parsed and allocated one message at a time — and the
/// supervision loop it used to run on is the same thread that answers
/// liveness pings, wedge detection, stop requests and steering
/// changes. A dump that outran the 3 s steering budget would time out
/// an operator's `steer off`: the rollback lever, blocked by a
/// monitoring scan (review finding). Monitoring must never be able to
/// delay the thing it monitors.
///
/// So the scan lives here: one thread, its own cadence, publishing
/// COMPLETED results into a slot the loop reads without blocking.
///
/// ## Every result is stamped with the scope it judged
///
/// Moving the scan off-thread created two ways to publish an answer
/// about the wrong configuration, and both hide a blackhole (review
/// findings on the async version):
///
/// - a scan already IN FLIGHT when the loop commits a new scope
///   finishes and publishes a verdict about the OLD exemptions;
/// - the worker then sleeps out its interval before adopting the new
///   one, so up to a minute passes with nothing re-examined.
///
/// The generation counter answers both. The loop bumps it when it
/// hands over a scope; the worker stamps each result with the
/// generation it actually scanned under; the loop discards any result
/// whose stamp is stale. And a handover WAKES the worker, so the
/// re-scan starts immediately rather than at the end of a sleep.
/// Until a result for the current generation arrives, the tripwire
/// reports that it has not scanned this configuration yet — never a
/// clean zero it has not earned.
pub struct DriftScanner {
    latest: std::sync::Arc<std::sync::Mutex<Option<StampedResult>>>,
    inbox: std::sync::Arc<(std::sync::Mutex<ScannerInbox>, std::sync::Condvar)>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DriftScanner {
    /// Start scanning every `every`, beginning immediately.
    pub fn spawn(mut watch: Box<dyn DriftWatch + Send>, every: std::time::Duration) -> Self {
        let latest: std::sync::Arc<std::sync::Mutex<Option<StampedResult>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let inbox = std::sync::Arc::new((
            std::sync::Mutex::new(ScannerInbox::default()),
            std::sync::Condvar::new(),
        ));
        let (l, ib) = (latest.clone(), inbox.clone());
        let handle = std::thread::Builder::new()
            .name("pf-drift-scan".into())
            .spawn(move || loop {
                // Adopt and stamp under ONE lock hold, so
                // `scanned_under` names exactly the scope the watcher
                // is about to scan with.
                let scanned_under = {
                    let mut inbox = ib.0.lock().expect("drift inbox lock");
                    if inbox.stop {
                        return;
                    }
                    if let Some((exempts, dst_only)) = inbox.pending.take() {
                        watch.set_scope(exempts, dst_only);
                    }
                    inbox.generation
                };
                let result = watch.uncovered();
                *l.lock().expect("drift result lock") = Some((scanned_under, result));

                let mut inbox = ib.0.lock().expect("drift inbox lock");
                let mut waited = std::time::Duration::ZERO;
                // Wake early for a new scope or a teardown; otherwise
                // sleep out the interval in slices so a stop is not
                // waiting on a full one.
                while !inbox.stop && inbox.pending.is_none() && waited < every {
                    let slice = std::time::Duration::from_millis(200);
                    let (guard, _) = ib.1.wait_timeout(inbox, slice).expect("drift inbox wait");
                    inbox = guard;
                    waited += slice;
                }
                if inbox.stop {
                    return;
                }
            })
            .ok();
        Self {
            latest,
            inbox,
            handle,
        }
    }

    /// The newest COMPLETED result, if one has arrived since the last
    /// look. `None` means nothing new — the caller keeps what it had.
    ///
    /// Returns the generation it was scanned under so the caller can
    /// tell a verdict about the current configuration from one about
    /// a superseded scope.
    pub fn take_result(&self) -> Option<StampedResult> {
        self.latest.lock().expect("drift result lock").take()
    }

    /// The scope generation currently in force.
    pub fn generation(&self) -> u64 {
        self.inbox.0.lock().expect("drift inbox lock").generation
    }

    /// Hand the scanner a scope to adopt, and wake it to re-scan now.
    pub fn set_scope(
        &self,
        exempts: Vec<Ipv4Prefix>,
        dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
    ) {
        let mut inbox = self.inbox.0.lock().expect("drift inbox lock");
        // Both under the lock the worker adopts and stamps under, so
        // there is no window where the counter has moved and the
        // scope has not.
        inbox.generation += 1;
        inbox.pending = Some((exempts, dst_only));
        self.inbox.1.notify_all();
    }
}

/// How long teardown waits for the scan thread before abandoning it.
///
/// A sleeping worker is woken by the stop notify and exits in
/// microseconds, which is the overwhelmingly common case; this only
/// has to be long enough to cover that wake.
const TEARDOWN_GRACE: std::time::Duration = std::time::Duration::from_millis(50);

impl Drop for DriftScanner {
    /// Ask the scan to stop, wait briefly, and ABANDON it if a dump is
    /// in flight.
    ///
    /// This runs on the supervision thread as it unwinds, AFTER the
    /// real teardown has killed VPP, released the VF and published its
    /// result — and `SupervisionService::stop()` gives that thread 900
    /// ms to finish before it tells the operator the teardown is
    /// incomplete and resources may still be held. A netlink dump has
    /// no cancellation and takes seconds on a DFZ table, so joining it
    /// unconditionally made a completed teardown report itself as an
    /// unfinished one, over a monitoring scan holding nothing (review
    /// finding).
    ///
    /// Abandoning is safe here in a way it would not be for the
    /// resource owners: this thread holds a read-only netlink socket,
    /// its watcher, and `Arc` clones of a result slot nobody reads any
    /// more. It owns no VPP process, no VF, no hugepage reservation —
    /// nothing whose lifetime a detach must account for — and the stop
    /// flag is already set, so it exits the moment its dump returns.
    /// (The previous comment here defended the join by calling the
    /// open socket a reason to wait; that conflated a thread holding a
    /// file descriptor with a thread holding the resources teardown
    /// exists to release.) A bounded receive keeps "the moment its
    /// dump returns" finite even if the kernel goes quiet.
    fn drop(&mut self) {
        {
            let mut inbox = self.inbox.0.lock().expect("drift inbox lock");
            inbox.stop = true;
            self.inbox.1.notify_all();
        }
        let Some(h) = self.handle.take() else { return };
        let deadline = std::time::Instant::now() + TEARDOWN_GRACE;
        while !h.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if h.is_finished() {
            let _ = h.join();
            return;
        }
        // Dropping the handle detaches the thread.
        tracing::debug!(
            "drift scan still in flight at teardown; detaching it rather than delaying detach"
        );
    }
}

/// The production scan: dump every IPv4 route in every table, compare.
#[cfg(target_os = "linux")]
pub struct KernelDriftWatch {
    pub reach: VppReach,
    /// The CURRENT exemptions. `steer-exempt` is hot-reloadable, so
    /// this is refreshed on every accepted reconfigure — a watcher
    /// frozen at attach would call a newly-unexempted path covered
    /// (the blackhole this exists to catch) and, worse, keep
    /// reporting a path the operator had just exempted BECAUSE the
    /// health message told them to (review finding).
    pub exempts: Vec<Ipv4Prefix>,
    /// Whether steering can divert anything, or only allowlisted
    /// destinations. Config-derived and restart-only, like the port
    /// directions it comes from.
    pub dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
}

#[cfg(target_os = "linux")]
impl DriftWatch for KernelDriftWatch {
    fn uncovered(&mut self) -> Result<DriftFindings, String> {
        let routes = dump_routes()?;
        // A rule dump that fails filters nothing rather than failing
        // the scan: the routes are the finding, the rules only narrow
        // them, and losing the narrowing costs noise where losing the
        // scan costs the blackhole.
        let tables = dump_rule_tables().unwrap_or_else(|e| {
            tracing::debug!(error = %e, "policy-rule dump failed; not filtering by table");
            None
        });
        let divertible = match &self.dst_only {
            Some(allow) => Divertible::OnlyDst(allow),
            None => Divertible::Any,
        };
        let scope = Scope {
            reach: &self.reach,
            exempts: &self.exempts,
            divertible,
            selected_tables: tables.as_deref(),
        };
        let found = uncovered_paths(&routes, &scope);
        Ok(DriftFindings {
            routes: found.iter().map(Uncovered::routes).sum(),
            lines: found.iter().map(Uncovered::to_string).collect(),
        })
    }

    fn set_scope(
        &mut self,
        exempts: Vec<Ipv4Prefix>,
        dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
    ) {
        self.exempts = exempts;
        self.dst_only = dst_only;
    }
}

/// One blocking RTM_GETROUTE dump across every table.
///
/// Hand-rolled on `netlink-sys` for the same reason [`crate::fdb`] is:
/// this crate runs a supervision loop, not an async runtime, and one
/// dump per minute does not earn one.
///
/// The LOCAL table is included deliberately. Its entries are the
/// router's own addresses, and steered traffic to those dies in VPP
/// exactly like tunnel-bound traffic does — that is the w23 blackhole
/// (110,917 packets in five minutes) which `steer-exempt` was
/// introduced to fix. A check that only looked at forwarding would
/// have missed the first instance of the very class it exists for.
#[cfg(target_os = "linux")]
pub fn dump_routes() -> Result<Vec<KernelRoute>, String> {
    use netlink_packet_core::{
        NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
    };
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteLwEnCapType, RouteMessage, RouteType,
    };
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    /// The kernel's name for a lightweight-encap action, for the
    /// operator's message. `None` is the overwhelming majority and is
    /// not an encapsulation — the kernel emits `RTA_ENCAP_TYPE` on
    /// plain routes too.
    fn encap_name(t: RouteLwEnCapType) -> Option<String> {
        Some(match t {
            RouteLwEnCapType::None => return None,
            RouteLwEnCapType::Mpls => "MPLS".to_string(),
            RouteLwEnCapType::Ip => "IP-in-IP".to_string(),
            RouteLwEnCapType::Ila => "ILA".to_string(),
            RouteLwEnCapType::Ip6 => "IPv6 tunnel".to_string(),
            RouteLwEnCapType::Seg6 => "SRv6".to_string(),
            RouteLwEnCapType::Seg6Local => "SRv6-local".to_string(),
            RouteLwEnCapType::Bpf => "BPF".to_string(),
            RouteLwEnCapType::Rpl => "RPL".to_string(),
            RouteLwEnCapType::Ioam6 => "IOAM6".to_string(),
            RouteLwEnCapType::Xfrm => "XFRM".to_string(),
            // The enum is `#[non_exhaustive]` and the kernel adds
            // types; an unrecognised one is still an encap action
            // and must still be reported, by number.
            other => format!("encap type {}", u16::from(other)),
        })
    }

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    // A receive that can block forever is a scan thread that never
    // settles — and teardown abandons an in-flight scan rather than
    // waiting on it, so "forever" would mean a thread and its socket
    // held for the daemon's life.
    crate::fdb::bound_recv(&socket)?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    // Interface names are resolved once per dump rather than per
    // route: a full table can carry thousands of entries out of a
    // handful of devices.
    let mut names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut out = Vec::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            // The kernel sets NLM_F_DUMP_INTR when the table changed
            // under the dump, which makes the result a mix of two
            // states rather than a snapshot. On a box with a live BGP
            // feed that is not rare, and a partial list fails the
            // dangerous way: a missing route reads as "no such path"
            // and a missing rule narrows the filter onto an active
            // table. Refuse it; the caller keeps its previous verdict
            // and the next scan is a minute away (review finding).
            if pkt.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err("the kernel interrupted the dump (NLM_F_DUMP_INTR): the \
                            table changed underneath it, so this result is not a \
                            snapshot"
                    .into());
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                    let mut dst: Option<std::net::Ipv4Addr> = None;
                    let mut oifs: Vec<u32> = Vec::new();
                    let mut nexthop_object = false;
                    let mut encap: Option<String> = None;
                    let mut table = u32::from(m.header.table);
                    for attr in &m.attributes {
                        match attr {
                            RouteAttribute::Destination(RouteAddress::Inet(a)) => dst = Some(*a),
                            RouteAttribute::Oif(i) => oifs.push(*i),
                            // `RTA_ENCAP_TYPE`: the route hands the
                            // packet to a lightweight tunnel before it
                            // leaves. See `KernelRoute::encap` for why
                            // the ordinary `oif` makes this the
                            // quietest failure in the dump.
                            RouteAttribute::EncapType(t) => {
                                encap = encap.take().or_else(|| encap_name(*t))
                            }
                            // ECMP puts its nexthops HERE and leaves
                            // RTA_OIF unset, so a route read only for
                            // RTA_OIF looks device-less and gets
                            // skipped — an all-tunnel ECMP route would
                            // blackhole under a clean health surface
                            // (review finding).
                            RouteAttribute::MultiPath(hops) => {
                                oifs.extend(hops.iter().map(|h| h.interface_index));
                                // Encapsulation is per PATH, and ECMP
                                // puts each path's attributes here. A
                                // route with one plain path and one
                                // encapped path is reported: VPP would
                                // install both and hash traffic into
                                // the one it cannot reproduce.
                                encap = encap.take().or_else(|| {
                                    hops.iter().flat_map(|h| h.attributes.iter()).find_map(|a| {
                                        match a {
                                            RouteAttribute::EncapType(t) => encap_name(*t),
                                            _ => None,
                                        }
                                    })
                                });
                            }
                            // RTA_TABLE carries ids past the u8 header
                            // field — policy tables live up there.
                            RouteAttribute::Table(t) => table = *t,
                            // RTA_NH_ID: a route carrying it names its
                            // devices in a nexthop object, nowhere this
                            // scan can read. See
                            // [`KernelRoute::via_nexthop_object`].
                            RouteAttribute::NhId(_) => nexthop_object = true,
                            _ => {}
                        }
                    }
                    out.push(KernelRoute {
                        prefix: Ipv4Prefix {
                            // No RTA_DST = the default route.
                            addr: dst.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                            prefix_len: m.header.destination_prefix_length,
                        },
                        oifs: oifs
                            .into_iter()
                            .map(|i| {
                                names
                                    .entry(i)
                                    .or_insert_with(|| crate::fdb::ifname(i))
                                    .clone()
                            })
                            .collect(),
                        table,
                        drops: matches!(
                            m.header.kind,
                            RouteType::BlackHole | RouteType::Unreachable | RouteType::Prohibit
                        ),
                        kernel_delivers: matches!(
                            m.header.kind,
                            RouteType::Local | RouteType::Broadcast | RouteType::Anycast
                        ),
                        via_nexthop_object: nexthop_object,
                        encap,
                    });
                }
                _ => {}
            }
            offset += len;
        }
    }
    Ok(out)
}

/// The table ids some policy rule can select, or `None` when they
/// cannot be enumerated safely and NOTHING may be filtered.
///
/// One `RTM_GETRULE` dump. See [`Scope::selected_tables`] for what
/// this models and, more importantly, what it deliberately does not.
///
/// `None` has two producers, and both are the safe direction:
///
/// - **an l3mdev rule** (`from all lookup [l3mdev-table]`), which
///   carries table id 0 and resolves to a VRF's table at forwarding
///   time. Its tables are not in the rule set at all, so filtering by
///   what IS there would drop every VRF route — and a tunnel route in
///   an active VRF would go unreported while steered traffic
///   blackholed (review finding). Mapping l3mdev to its VRF tables
///   means enumerating VRF devices and their table ids; until that
///   exists, a host with one gets no filtering, which is exactly the
///   behaviour before the filter was added.
/// - **an empty result.** Filtering by an empty set would skip every
///   route and report a permanently clean scan, which is the failure
///   this whole module exists to prevent.
#[cfg(target_os = "linux")]
pub fn dump_rule_tables() -> Result<Option<Vec<u32>>, String> {
    use netlink_packet_core::{
        NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
    };
    use netlink_packet_route::rule::{RuleAttribute, RuleMessage};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    crate::fdb::bound_recv(&socket)?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut rule = RuleMessage::default();
    rule.header.family = AddressFamily::Inet;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetRule(rule));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    let mut out: Vec<u32> = Vec::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            // The kernel sets NLM_F_DUMP_INTR when the table changed
            // under the dump, which makes the result a mix of two
            // states rather than a snapshot. On a box with a live BGP
            // feed that is not rare, and a partial list fails the
            // dangerous way: a missing route reads as "no such path"
            // and a missing rule narrows the filter onto an active
            // table. Refuse it; the caller keeps its previous verdict
            // and the next scan is a minute away (review finding).
            if pkt.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err("the kernel interrupted the dump (NLM_F_DUMP_INTR): the \
                            table changed underneath it, so this result is not a \
                            snapshot"
                    .into());
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(m)) => {
                    // FRA_TABLE carries ids past the u8 header field,
                    // exactly as RTA_TABLE does for routes.
                    let mut table = u32::from(m.header.table);
                    for attr in &m.attributes {
                        match attr {
                            RuleAttribute::Table(t) => table = *t,
                            // The VRF case: this rule names no table
                            // of its own and picks one per packet, so
                            // the enumeration cannot be complete.
                            RuleAttribute::L3MDev(true) => return Ok(None),
                            _ => {}
                        }
                    }
                    if table != 0 && !out.contains(&table) {
                        out.push(table);
                    }
                }
                _ => {}
            }
            offset += len;
        }
    }
    // Empty means "no rule named a table", which cannot be used to
    // filter — see this function's doc.
    Ok((!out.is_empty()).then_some(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn p(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Prefix {
        Ipv4Prefix {
            addr: Ipv4Addr::new(a, b, c, d),
            prefix_len: len,
        }
    }

    fn route(prefix: Ipv4Prefix, oif: &str) -> KernelRoute {
        KernelRoute {
            prefix,
            oifs: vec![oif.to_string()],
            table: 100,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            encap: None,
        }
    }

    fn reach() -> VppReach {
        VppReach {
            members: vec!["eth3".into(), "eth4".into()],
            local_devices: vec!["br1337".into()],
        }
    }

    fn find(routes: &[KernelRoute], exempts: &[Ipv4Prefix]) -> Vec<Uncovered> {
        uncovered_paths(
            routes,
            &Scope {
                reach: &reach(),
                exempts,
                divertible: Divertible::Any,
                selected_tables: None,
            },
        )
    }

    /// The w26 shape: tunnel-bound routes are findings, and only the
    /// ones no exemption covers.
    #[test]
    fn tunnel_paths_are_findings_until_an_exemption_covers_them() {
        let routes = vec![
            route(p(23, 191, 201, 0, 24), "vti64"), // remote site: finding
            route(p(23, 191, 200, 2, 32), "vti64"), // host inside the local /24
            route(p(0, 0, 0, 0, 0), "eth3"),        // default via a member: fine
            route(p(23, 191, 200, 0, 24), "br1337"), // local delivery: fine
            route(p(10, 0, 0, 0, 8), "eth4"),       // member: fine
        ];
        let found = find(&routes, &[]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|u| u.to_string().contains("via vti64")));

        let exempts = [p(23, 191, 201, 0, 24), p(23, 191, 200, 2, 32)];
        assert!(find(&routes, &exempts).is_empty());
    }

    /// Containment, not overlap: a /32 exemption inside a /24 route
    /// does NOT cover the /24.
    #[test]
    fn an_exemption_must_contain_the_route_not_merely_overlap_it() {
        let routes = vec![route(p(23, 191, 201, 0, 24), "vti64")];
        assert_eq!(
            find(&routes, &[p(23, 191, 201, 5, 32)]).len(),
            1,
            "a /32 inside the route must not silence the /24"
        );
        assert!(find(&routes, &[p(23, 191, 0, 0, 16)]).is_empty());
    }

    /// Routes the kernel drops itself are not findings: VPP dropping
    /// the same packet is the same outcome, one hop earlier.
    #[test]
    fn routes_the_kernel_itself_drops_are_not_findings() {
        let mut blackhole = route(p(198, 18, 0, 0, 15), "vti64");
        blackhole.drops = true;
        let mut no_oif = route(p(203, 0, 113, 0, 24), "vti64");
        no_oif.oifs.clear();
        assert!(find(&[blackhole, no_oif], &[]).is_empty());
    }

    /// Broadcast and multicast are exempted on every steered port
    /// without a directive.
    #[test]
    fn the_built_in_exemptions_count_as_cover() {
        let routes = vec![
            route(p(224, 0, 0, 0, 4), "vti64"),
            route(p(255, 255, 255, 255, 32), "vti64"),
        ];
        assert!(find(&routes, &[]).is_empty());
    }

    /// A LOCAL route is an address the kernel terminates, so device
    /// reachability says nothing about it — VPP has no local delivery
    /// at any interface. Skipping these because their oif is a member
    /// or bridge is exactly how the w23 class (110,917 packets to a
    /// gateway address in five minutes) would go unreported by a scan
    /// whose docs claimed to cover it (review finding).
    #[test]
    fn a_local_address_on_a_service_bridge_is_a_finding_despite_the_device() {
        let mut gw = route(p(23, 191, 200, 1, 32), "br1337");
        gw.kernel_delivers = true;
        gw.table = 255;
        let found = find(&[gw.clone()], &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(matches!(
            found[0],
            Uncovered::Path {
                kernel_delivers: true,
                ..
            }
        ));
        assert!(
            found[0]
                .to_string()
                .contains("delivered by the kernel on br1337"),
            "the message must read as termination, not a path: {}",
            found[0]
        );
        // And the exemption an operator would add silences it.
        assert!(find(&[gw], &[p(23, 191, 200, 1, 32)]).is_empty());
    }

    /// A service bridge's directed broadcast (`.255`) is
    /// `RTN_BROADCAST` with the bridge as its oif — kernel-owned
    /// delivery VPP cannot reproduce, not a forwarding path — so the
    /// device check must not wave it through just because the bridge
    /// is a local device (review finding, one round after the same
    /// thing was fixed for `RTN_LOCAL`).
    #[test]
    fn a_service_bridges_directed_broadcast_is_kernel_delivery_too() {
        let mut bcast = route(p(23, 191, 200, 255, 32), "br1337");
        bcast.kernel_delivers = true;
        bcast.table = 255;
        let found = find(std::slice::from_ref(&bcast), &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].to_string().contains("delivered by the kernel"),
            "{}",
            found[0]
        );
        assert!(find(&[bcast], &[p(23, 191, 200, 255, 32)]).is_empty());
    }

    /// Local addresses NOT on a steered segment are deliberately out
    /// of scope: the 16-slot budget cannot hold an exemption for every
    /// address on the box, and an alarm with no available remedy is
    /// one operators learn to ignore. Documented, with the null-drop
    /// gauge as the backstop.
    #[test]
    fn local_addresses_off_the_steered_segments_are_out_of_scope() {
        let mut transit = route(p(194, 110, 60, 51, 32), "eth3");
        transit.kernel_delivers = true;
        let mut loopback = route(p(127, 0, 0, 1, 32), "lo");
        loopback.kernel_delivers = true;
        assert!(find(&[transit, loopback], &[]).is_empty());
    }

    /// ECMP encodes nexthops in RTA_MULTIPATH, leaving RTA_OIF unset.
    /// A route read only for RTA_OIF looks device-less and is skipped
    /// — so an all-tunnel ECMP route would blackhole under a clean
    /// health surface (review finding). Any reachable path makes the
    /// route deliverable, because VPP installs the paths it can
    /// resolve and forwards over those.
    #[test]
    fn a_multipath_route_is_judged_by_all_its_nexthops() {
        let all_tunnel = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: vec!["vti64".into(), "wg0".into()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            encap: None,
        };
        assert_eq!(find(&[all_tunnel], &[]).len(), 1);

        let mixed = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: vec!["vti64".into(), "eth3".into()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            encap: None,
        };
        assert!(
            find(&[mixed], &[]).is_empty(),
            "one resolvable path is enough for VPP to forward the prefix"
        );
    }

    /// A lightweight-encap route (`ip route ... encap mpls 100 dev
    /// eth3`) leaves by an ORDINARY device — a member port, here — so
    /// every reachability test in this scan passes it, and the mirror,
    /// which has nowhere to put a label stack, would forward the
    /// packet bare out the same port (review finding). The device is
    /// not the hazard; the action is.
    #[test]
    fn an_encapsulating_route_is_a_finding_even_out_a_member_port() {
        let mut mpls = route(p(203, 0, 113, 0, 24), "eth3");
        mpls.encap = Some("MPLS".into());
        let found = find(std::slice::from_ref(&mpls), &[]);
        assert_eq!(
            found.len(),
            1,
            "a member-port oif must not clear an encap action: {found:?}"
        );
        let msg = found[0].to_string();
        assert!(
            msg.contains("MPLS") && msg.contains("bare"),
            "the message must name the action, not the reachability: {msg}"
        );
        // And an exemption still silences it — exempted traffic never
        // reaches VPP, so there is nothing to misforward.
        assert!(find(&[mpls], &[p(203, 0, 113, 0, 24)]).is_empty());
    }

    /// Encapsulation is a property of a PATH, so an ECMP route with
    /// one plain member path and one encapped path is still a finding:
    /// VPP installs both and hashes traffic into the one it cannot
    /// reproduce. The any-path-reachable rule must not clear it.
    #[test]
    fn one_encapped_path_in_an_ecmp_group_is_enough() {
        let mixed = KernelRoute {
            prefix: p(203, 0, 113, 0, 24),
            oifs: vec!["eth3".into(), "eth4".into()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            encap: Some("SRv6".into()),
        };
        assert_eq!(find(&[mixed], &[]).len(), 1);
    }

    /// Under dst-only steering the NIC diverts only packets addressed
    /// inside the allowlist, so a path outside it can never enter VPP
    /// and must not cost an exemption slot (review finding). Any src
    /// rule anywhere restores the everything-is-at-risk scope.
    #[test]
    fn dst_only_steering_scopes_the_scan_to_divertible_destinations() {
        use packetframe_common::fib::IpPrefix;
        let allow = [IpPrefix::V4 {
            addr: [23, 191, 200, 0],
            prefix_len: 24,
        }];
        let routes = vec![
            route(p(23, 191, 200, 2, 32), "vti64"), // inside the allowlist
            route(p(198, 51, 100, 0, 24), "vti64"), // outside it
        ];
        let scoped = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::OnlyDst(&allow),
                selected_tables: None,
            },
        );
        assert_eq!(scoped.len(), 1, "{scoped:?}");
        assert!(
            scoped[0].to_string().contains("23.191.200.2/32"),
            "{scoped:?}"
        );

        // A src rule anywhere means any destination can be diverted.
        assert_eq!(find(&routes, &[]).len(), 2);
    }

    /// A table no policy rule names cannot be consulted by any
    /// packet, so a tunnel route parked in an unreferenced VRF must
    /// not cost an exemption slot (review finding). Only SELECTION is
    /// modelled — fwmark/iif/from are not, because over-reporting is
    /// the safe direction and a permissive mistake in a rule walk
    /// re-opens the hole this scan closes.
    #[test]
    fn routes_in_tables_no_rule_selects_are_not_findings() {
        let mut in_use = route(p(23, 191, 201, 0, 24), "vti64");
        in_use.table = 100;
        let mut orphan = route(p(198, 51, 100, 0, 24), "vti64");
        orphan.table = 4242;
        let routes = [in_use, orphan];
        let selected = [100u32, 254, 255];
        let found = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::Any,
                selected_tables: Some(&selected),
            },
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].table(), Some(100));
        // Unknown rule set filters nothing: losing the narrowing
        // costs noise, losing the scan costs the blackhole. This is
        // the arm an l3mdev (VRF) rule takes — its tables resolve per
        // packet and are absent from the rule set, so filtering by
        // what IS there would drop every VRF route and report clean
        // while steered traffic blackholed (review finding). Same arm
        // for a failed dump, and for an empty enumeration, which
        // would otherwise skip every route on the box.
        assert_eq!(find(&routes, &[]).len(), 2);
        let empty_selection: [u32; 0] = [];
        let blind = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::Any,
                selected_tables: Some(&empty_selection),
            },
        );
        assert!(
            blind.is_empty(),
            "an empty selection filters everything — which is why the dump returns None \
             for it rather than an empty Vec: {blind:?}"
        );
    }

    /// The scope derivation is shared by attach and reconfigure, so a
    /// hot allowlist or direction edit cannot leave the scan judging
    /// the config from attach time (review finding).
    #[test]
    fn the_diversion_scope_follows_config_not_attach_time() {
        use packetframe_common::config::VppSteerDirection as D;
        use packetframe_common::fib::IpPrefix;
        let allow = [IpPrefix::V4 {
            addr: [23, 191, 200, 0],
            prefix_len: 24,
        }];
        let port = |steer: bool, dir: Option<D>| ("eth4".to_string(), 1u16, steer, Vec::new(), dir);

        // Every port dst → scoped to the allowlist.
        let scoped = divertible_scope(&[port(true, Some(D::Dst))], D::Both, &allow);
        assert_eq!(scoped.as_deref(), Some(&allow[..]));

        // One src port anywhere → everything is at risk.
        assert!(
            divertible_scope(
                &[port(true, Some(D::Dst)), port(false, Some(D::Src))],
                D::Dst,
                &allow
            )
            .is_none(),
            "a src port makes any destination divertible"
        );
        // The global default applies to ports that declare nothing.
        assert!(divertible_scope(&[port(true, None)], D::Both, &allow).is_none());
        assert_eq!(
            divertible_scope(&[port(true, None)], D::Dst, &allow).as_deref(),
            Some(&allow[..])
        );
        // No ports at all: conservative.
        assert!(divertible_scope(&[], D::Dst, &allow).is_none());
    }

    /// Under dst-only steering only the route's INTERSECTION with the
    /// allowlist can be diverted, so an exemption covering that
    /// intersection covers the whole hazard — demanding one for the
    /// entire route would send the operator to install a broader rule
    /// than the risk warrants (review finding).
    #[test]
    fn dst_only_coverage_is_judged_on_the_divertible_intersection() {
        use packetframe_common::fib::IpPrefix;
        // One host of a tunnel-backed /24 is allowlisted, so only that
        // host can be diverted at all.
        let allow = [IpPrefix::V4 {
            addr: [23, 191, 201, 7],
            prefix_len: 32,
        }];
        let routes = [route(p(23, 191, 201, 0, 24), "vti64")];
        let scoped = |exempts: &[Ipv4Prefix]| {
            uncovered_paths(
                &routes,
                &Scope {
                    reach: &reach(),
                    exempts,
                    divertible: Divertible::OnlyDst(&allow),
                    selected_tables: None,
                },
            )
        };
        assert_eq!(scoped(&[]).len(), 1, "uncovered: the /32 can be diverted");
        assert!(
            scoped(&[p(23, 191, 201, 7, 32)]).is_empty(),
            "exempting the one divertible host covers the whole hazard"
        );

        // Under src steering the same /32 exemption is NOT enough:
        // every address in the /24 can be diverted there.
        let any = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[p(23, 191, 201, 7, 32)],
                divertible: Divertible::Any,
                selected_tables: None,
            },
        );
        assert_eq!(any.len(), 1, "{any:?}");
    }

    /// A route using a nexthop object names its devices nowhere this
    /// scan can read. Left as a device-less route it would be SKIPPED
    /// — a tunnel-backed nhid route blackholing under a clean scan
    /// (review finding) — so the scan reports its own blind spot
    /// instead, once, rather than flooding a finding per route or
    /// guessing at reachability.
    #[test]
    fn routes_via_nexthop_objects_are_reported_as_a_coverage_gap() {
        let opaque = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: Vec::new(),
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: true,
            encap: None,
        };
        let found = find(&[opaque.clone(), opaque.clone()], &[]);
        assert_eq!(found.len(), 1, "one summary, not one per route: {found:?}");
        assert_eq!(found[0], Uncovered::Opaque(2));
        assert_eq!(
            found[0].routes(),
            2,
            "one LINE, but it stands for two routes — the gauge counts routes"
        );
        let line = found[0].to_string();
        assert!(line.contains("nhid"), "{line}");
        assert!(line.contains("ip nexthop show"), "names the tool: {line}");

        // An exemption covering it makes it a non-issue, exactly as
        // for a route whose device we CAN see.
        assert!(find(std::slice::from_ref(&opaque), &[p(198, 51, 100, 0, 24)]).is_empty());

        // And a table no rule selects silences it for the same reason
        // it silences a readable route: no packet can use it, so
        // nobody should be sent to inspect nexthops for it (review
        // finding — this branch bypassed the filter).
        let mut parked = opaque;
        parked.table = 4242;
        let selected = [254u32, 255];
        let scoped = uncovered_paths(
            &[parked],
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::Any,
                selected_tables: Some(&selected),
            },
        );
        assert!(scoped.is_empty(), "{scoped:?}");
    }

    /// The scanner's scope hand-off is atomic: a result is stamped
    /// with the scope it actually scanned under, never one that
    /// arrived mid-pass.
    ///
    /// A bare counter bumped outside the inbox lock let the worker
    /// adopt nothing, read the incremented value, and stamp a scan of
    /// the OLD exemptions as the NEW scope's — which the loop would
    /// then accept as current (review finding). This drives the seam
    /// directly rather than racing threads, which is the part that
    /// can actually be asserted.
    #[test]
    fn a_result_is_stamped_with_the_scope_it_scanned_under() {
        use std::sync::{Arc, Mutex};

        /// Records the scope in force at each `uncovered()` call.
        struct Recorder {
            seen: Arc<Mutex<Vec<usize>>>,
            exempts: usize,
        }
        impl DriftWatch for Recorder {
            fn uncovered(&mut self) -> Result<DriftFindings, String> {
                self.seen.lock().unwrap().push(self.exempts);
                Ok(DriftFindings::default())
            }
            fn set_scope(
                &mut self,
                exempts: Vec<Ipv4Prefix>,
                _dst: Option<Vec<packetframe_common::fib::IpPrefix>>,
            ) {
                self.exempts = exempts.len();
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let scanner = DriftScanner::spawn(
            Box::new(Recorder {
                seen: seen.clone(),
                exempts: 0,
            }),
            std::time::Duration::from_millis(50),
        );
        // Generation starts at zero and only a hand-off moves it.
        assert_eq!(scanner.generation(), 0);
        scanner.set_scope(vec![p(10, 0, 0, 0, 8)], None);
        assert_eq!(scanner.generation(), 1, "the hand-off bumps it");

        // Whatever the worker publishes, its stamp is a generation
        // that existed, and the newest one is eventually reported.
        let mut stamped_current = false;
        for _ in 0..200 {
            if let Some((gen, _)) = scanner.take_result() {
                assert!(gen <= scanner.generation(), "no stamp from the future");
                if gen == 1 {
                    stamped_current = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            stamped_current,
            "a scan under the new scope must be published"
        );
        assert!(
            seen.lock().unwrap().contains(&1),
            "and it must have scanned with the new exemptions"
        );
    }

    /// Teardown does not wait out a scan in flight.
    ///
    /// This drop runs on the supervision thread after the real
    /// teardown is done, and `SupervisionService::stop()` gives that
    /// thread 900 ms before it tells the operator resources may still
    /// be held. A full route dump takes seconds, so joining it made a
    /// finished teardown report itself unfinished (review finding).
    #[test]
    fn teardown_abandons_a_scan_in_flight_instead_of_waiting_for_it() {
        use std::sync::{Arc, Condvar, Mutex};

        /// Blocks inside `uncovered()` the way a real dump does, and
        /// says when it has entered.
        struct Blocking {
            entered: Arc<(Mutex<bool>, Condvar)>,
        }
        impl DriftWatch for Blocking {
            fn uncovered(&mut self) -> Result<DriftFindings, String> {
                {
                    let mut in_dump = self.entered.0.lock().unwrap();
                    *in_dump = true;
                    self.entered.1.notify_all();
                }
                std::thread::sleep(std::time::Duration::from_millis(1500));
                Ok(DriftFindings::default())
            }
            fn set_scope(
                &mut self,
                _e: Vec<Ipv4Prefix>,
                _d: Option<Vec<packetframe_common::fib::IpPrefix>>,
            ) {
            }
        }

        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let scanner = DriftScanner::spawn(
            Box::new(Blocking {
                entered: entered.clone(),
            }),
            std::time::Duration::from_secs(60),
        );
        // Only meaningful once the worker is actually inside the dump.
        let mut in_dump = entered.0.lock().unwrap();
        while !*in_dump {
            let (g, timed_out) = entered
                .1
                .wait_timeout(in_dump, std::time::Duration::from_secs(5))
                .unwrap();
            in_dump = g;
            assert!(!timed_out.timed_out(), "the scan never started");
        }
        drop(in_dump);

        let started = std::time::Instant::now();
        drop(scanner);
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(500),
            "teardown waited {waited:?} on a monitoring scan; the detach budget is 900 ms for \
             the whole supervision thread"
        );
    }

    /// The operator-facing line names the three things needed to act:
    /// what, out of where, and which table to look in.
    #[test]
    fn a_finding_names_prefix_device_and_table() {
        let found = find(&[route(p(23, 191, 201, 0, 24), "vti64")], &[]);
        let line = found[0].to_string();
        assert!(line.contains("23.191.201.0/24"), "{line}");
        assert!(line.contains("vti64"), "{line}");
        assert!(line.contains("table 100"), "{line}");
    }
}
