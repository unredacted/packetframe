//! Bridges the sink's route state ([`crate::sink`]) to VPP's binary
//! API ([`crate::vpp_api`]).
//!
//! Everything here is the *translation and pacing* layer: turning a
//! prefix plus resolved nexthops into `ip_route_add_del`, pipelining
//! those onto the socket, and feeding VPP's answers back into the
//! ledger. It owns no policy — what should be installed is the sink's
//! question, and how bytes reach VPP is the transport's.
//!
//! **Pipelining is the point.** VPP answers every request, so a naive
//! loop pays a round trip per route: at ~1.05M v4 routes that is tens
//! of seconds of pure latency against a 60 s convergence budget which
//! also has to cover VPP installing them. [`Drainer`] keeps a window
//! of requests in flight and reconciles replies afterwards, so the
//! latency is paid once per window.
//!
//! **A failed drain leaves nothing lost.** Any op that was not
//! positively acknowledged goes back into the pending map, and the
//! ledger unwinds to what VPP is actually known to hold. That is what
//! makes a mid-load transport failure a retry rather than a silently
//! partial FIB.

use std::collections::HashMap;
use std::net::IpAddr;

use packetframe_common::fib::IpPrefix;

use crate::sink::{NexthopTarget, PendingMap, PendingOp, RouteLedger, RouteState};
use crate::vpp_api::generated::{
    Address, AddressUnion, FibPath, IpRoute, IpRouteAddDel, IpRouteAddDelReply, Prefix,
    ADDRESS_IP4, ADDRESS_IP6, FIB_API_PATH_FLAG_NONE, FIB_API_PATH_NH_PROTO_IP4,
    FIB_API_PATH_NH_PROTO_IP6, FIB_API_PATH_TYPE_NORMAL,
};
use crate::vpp_api::{Transport, TransportError};

/// How many requests may be in flight before we stop and read.
///
/// Bounded for backpressure: without a cap, a full-table load would
/// queue a million requests into the socket buffer and VPP's input
/// queue, turning a bounded memory cost into an unbounded one on both
/// sides. 256 keeps the syscall amortisation while capping the
/// unacknowledged work — and, more importantly, caps how much has to
/// be requeued when a drain fails mid-window.
pub const DEFAULT_WINDOW: usize = 256;

/// Wire limit on paths per route: `n_paths` is a `u8`.
///
/// Load-bearing rather than theoretical. The encoder writes
/// `paths.len() as u8` while still serialising every element, so a set
/// larger than this puts a **wrapped count** on the wire followed by more
/// path records than it declares — VPP either rejects the route or
/// installs a truncated set, and a surviving owned path would still pass
/// readback verification. Silent wire corruption is not a shape to leave
/// reachable, however unlikely the input.
pub const MAX_FIB_PATHS: usize = u8::MAX as usize;

/// VPP interface indices for the ports the module owns.
///
/// Populated at attach from `dev_create_port_if_reply`, which is where
/// VPP assigns them — they are not derivable from the PCI address or
/// the port name, so this map is the only link between the sink's
/// device-name view and the FIB paths it has to encode.
#[derive(Debug, Default, Clone)]
pub struct PortIndex {
    /// `(port, vlan)` → sw_if_index. A VLAN nexthop resolves to a VPP
    /// sub-interface, which carries its OWN index — using the parent
    /// port's would install every VLAN route onto the untagged
    /// interface.
    idx: HashMap<(String, Option<u16>), u32>,
}

impl PortIndex {
    pub fn insert(&mut self, port: impl Into<String>, vlan: Option<u16>, sw_if_index: u32) {
        self.idx.insert((port.into(), vlan), sw_if_index);
    }

    pub fn get(&self, target: &NexthopTarget) -> Option<u32> {
        let key = match target {
            NexthopTarget::Vf { port } => (port.clone(), None),
            NexthopTarget::Subif { port, vlan } => (port.clone(), Some(*vlan)),
        };
        self.idx.get(&key).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    /// Every interface index we own.
    ///
    /// Readback verification uses this to reject a FIB path pointing
    /// anywhere else — most importantly index 0, `local0`, which
    /// forwards nothing while looking installed.
    pub fn indices(&self) -> std::collections::HashSet<u32> {
        self.idx.values().copied().collect()
    }
}

/// Wire form of an address, family tag and all.
pub fn to_address(ip: IpAddr) -> Address {
    let mut un = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => {
            un[..4].copy_from_slice(&v4.octets());
            Address {
                af: ADDRESS_IP4,
                un: AddressUnion(un),
            }
        }
        IpAddr::V6(v6) => {
            un.copy_from_slice(&v6.octets());
            Address {
                af: ADDRESS_IP6,
                un: AddressUnion(un),
            }
        }
    }
}

/// A delete for `prefix`. VPP matches deletes on the prefix alone, so
/// no paths are needed — and sending them would only invite a mismatch
/// against whatever was actually installed.
fn withdraw_msg(prefix: IpPrefix) -> IpRouteAddDel {
    IpRouteAddDel {
        context: 0,
        is_add: false,
        is_multipath: false,
        route: IpRoute {
            table_id: 0,
            stats_index: 0,
            prefix: to_prefix(prefix),
            n_paths: 0,
            paths: Vec::new(),
        },
    }
}

/// Wire form of a prefix.
pub fn to_prefix(p: IpPrefix) -> Prefix {
    match p {
        IpPrefix::V4 { addr, prefix_len } => {
            let mut un = [0u8; 16];
            un[..4].copy_from_slice(&addr);
            Prefix {
                address: Address {
                    af: ADDRESS_IP4,
                    un: AddressUnion(un),
                },
                len: prefix_len,
            }
        }
        IpPrefix::V6 { addr, prefix_len } => Prefix {
            address: Address {
                af: ADDRESS_IP6,
                un: AddressUnion(addr),
            },
            len: prefix_len,
        },
    }
}

/// One resolved path: where it exits and via which neighbor.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedPath {
    pub nexthop: IpAddr,
    pub target: NexthopTarget,
}

/// Build the FIB paths for a route.
///
/// Returns `None` when a target has no interface index yet — that is
/// an attach-ordering fault (routes arriving before the device's
/// interface exists), and installing the route with index 0 would
/// silently point it at `local0`.
pub fn build_paths(paths: &[ResolvedPath], ports: &PortIndex) -> Option<Vec<FibPath>> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let sw_if_index = ports.get(&p.target)?;
        let proto = match p.nexthop {
            IpAddr::V4(_) => FIB_API_PATH_NH_PROTO_IP4,
            IpAddr::V6(_) => FIB_API_PATH_NH_PROTO_IP6,
        };
        let mut fp = FibPath {
            sw_if_index,
            table_id: 0,
            rpf_id: 0,
            // Equal weight: ECMP share is VPP's to compute, and this
            // fleet runs no unequal-cost groups. Preference 0 keeps
            // every path in the same tier — the sink has already
            // filtered to the winning local-pref tier upstream.
            weight: 1,
            preference: 0,
            r#type: FIB_API_PATH_TYPE_NORMAL,
            flags: FIB_API_PATH_FLAG_NONE,
            proto,
            nh: Default::default(),
            n_labels: 0,
            label_stack: Default::default(),
        };
        // The nexthop address goes in the path's own union, which is
        // the bare address — no family tag, since `proto` above
        // already carries it.
        match p.nexthop {
            IpAddr::V4(v4) => fp.nh.address.0[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => fp.nh.address.0.copy_from_slice(&v6.octets()),
        }
        out.push(fp);
    }
    Some(out)
}

/// What one drain accomplished.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainStats {
    /// Routes VPP acknowledged as installed.
    pub installed: u64,
    /// Routes VPP acknowledged as withdrawn.
    pub withdrawn: u64,
    /// Held back by capacity — retried when headroom returns.
    pub withheld: u64,
    /// No nexthop resolved to a VPP-owned device.
    pub unresolvable: u64,
    /// VPP returned a non-zero retval. Requeued, not dropped.
    pub rejected: u64,
    /// Not attempted because a target had no interface index yet.
    /// **Requeued**, so a later drain installs it once attach
    /// completes — a deferred route is postponed, never dropped.
    pub deferred: u64,
    /// Skipped because the prefix's address family is not carried by
    /// VPP on this platform. See [`FamilyPolicy`].
    pub out_of_family: u64,
    /// Previously-withheld ops moved back into the active map because
    /// headroom returned. They install on the next drain.
    pub released: u64,
    /// Routes whose resolved path set exceeded [`MAX_FIB_PATHS`] and was
    /// truncated to fit the wire's `u8` count.
    ///
    /// Capped rather than refused: 255 of 300 paths still forwards
    /// correctly, just with less spread, while refusing the route
    /// blackholes the prefix outright. Counted because a non-zero value
    /// means the route source is producing ECMP sets nobody designed
    /// for — the reference fleet measured **zero** ECMP groups.
    pub paths_capped: u64,
}

impl DrainStats {
    pub fn attempted(&self) -> u64 {
        self.installed + self.withdrawn + self.rejected
    }
}

/// Which address families VPP carries.
///
/// Not a tuning knob — a record of what the hardware will do. Gate 0b
/// round 4 established that `ip6` ntuple rules are rejected by the AF
/// (error 710: the vendor NPC profile has no v6 extraction), so **no
/// IPv6 packet can ever be MCAM-steered into VPP** and v6 stays on the
/// XDP custom-FIB path. Installing v6 routes into a FIB that will
/// never be consulted costs heap, costs convergence time against the
/// 60 s budget, and — worst — lets ~250k unreachable v6 routes consume
/// capacity slots that would otherwise hold v4 routes we actually
/// forward on.
///
/// It is a policy rather than a hardcoded filter because the v6
/// roadmap is explicit: retest `ip6` ntuple at every UniFi kernel bump,
/// since the MKEX profile ships with the AF driver. When it starts
/// working this becomes [`FamilyPolicy::Both`] and a full resync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FamilyPolicy {
    /// v4 only — the measured reality on this NIC.
    #[default]
    V4Only,
    /// Both families, for a platform whose classifier can steer v6.
    Both,
}

impl FamilyPolicy {
    pub fn carries(self, prefix: IpPrefix) -> bool {
        match self {
            FamilyPolicy::Both => true,
            FamilyPolicy::V4Only => matches!(prefix, IpPrefix::V4 { .. }),
        }
    }
}

/// Truncate a path set to what the wire can describe, reporting whether
/// it had to.
///
/// See [`MAX_FIB_PATHS`]: past 255 the declared count wraps while every
/// element is still serialised, so VPP reads a wrapped count followed by
/// more path records than it was told about — the route is rejected or
/// installed with a truncated set, and a surviving owned path would still
/// pass readback verification.
///
/// Capped rather than refused because 255 of 300 paths still forwards
/// correctly, just with less spread, whereas refusing blackholes the
/// prefix outright. Deterministic (a plain prefix of the resolved order)
/// so the same input always produces the same FIB.
pub fn cap_paths(paths: &mut Vec<FibPath>) -> bool {
    if paths.len() <= MAX_FIB_PATHS {
        return false;
    }
    paths.truncate(MAX_FIB_PATHS);
    true
}

/// Pipelines pending route operations onto a [`Transport`].
pub struct Drainer {
    window: usize,
    families: FamilyPolicy,
}

/// What [`Drainer::begin`] decided to do with one pending op.
enum Begun {
    /// A request went out; await its reply. `op` is the *effective*
    /// operation, which is not always the pending one — an installed
    /// prefix that becomes unresolvable is sent as a withdrawal.
    ///
    /// `derived` marks exactly that case: a withdrawal we invented
    /// because resolution failed, as opposed to one the route source
    /// asked for. The two must complete differently (see
    /// [`Drainer::finish`]) — an authoritative withdrawal means the
    /// prefix is gone, a derived one means the prefix is still
    /// advertised but unresolvable, and conflating them loses the hole.
    Sent {
        context: u32,
        op: PendingOp,
        derived: bool,
    },
    /// Resolved without touching the socket; already counted.
    Done,
    /// Cannot be attempted yet. Must go back into the pending map.
    Defer,
    /// Refused by capacity. Parked until headroom returns — NOT put
    /// back in the active map, which the caller drains to empty.
    Withhold,
}

/// One request awaiting its reply.
struct InFlight {
    context: u32,
    prefix: IpPrefix,
    /// The operation actually sent, which decides how the reply is
    /// applied to the ledger.
    sent: PendingOp,
    /// The operation as it sat in the pending map. Requeueing this
    /// rather than `sent` matters: a retry must re-run classification
    /// from the original intent, not re-apply a withdrawal we derived
    /// from state that may have changed.
    original: PendingOp,
    /// Whether `sent` is a withdrawal this drainer derived rather than
    /// one the route source asked for.
    derived: bool,
}

impl Default for Drainer {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

impl Drainer {
    pub fn new(window: usize) -> Self {
        Self {
            window: window.max(1),
            families: FamilyPolicy::default(),
        }
    }

    /// Override which families reach VPP. See [`FamilyPolicy`].
    pub fn with_families(mut self, families: FamilyPolicy) -> Self {
        self.families = families;
        self
    }

    /// Drain up to `max_ops` pending operations.
    ///
    /// On transport failure, everything not positively acknowledged is
    /// put back: in-flight ops are requeued and their ledger
    /// reservations unwound, and the untouched tail of the batch goes
    /// back too. The caller may retry against a fresh connection
    /// without having lost or double-counted anything.
    // The Err variant carries partial `DrainStats` alongside the
    // transport error, which is the point: the caller needs to know what
    // did land before the socket broke. That tuple crosses clippy's
    // 128-byte threshold now that `DrainStats` has ten counters.
    //
    // Not boxed. This returns **once per drain batch** (4096 routes), not
    // per route, so the copy is noise — and boxing would put a heap
    // allocation on the failure path, at the exact moment the transport
    // is already failing and we are unwinding a window of in-flight
    // requests.
    #[allow(clippy::result_large_err)]
    pub fn drain(
        &self,
        pending: &mut PendingMap,
        ledger: &mut RouteLedger,
        resolve: &dyn Fn(&[IpAddr]) -> Vec<ResolvedPath>,
        ports: &PortIndex,
        transport: &mut Transport,
        max_ops: usize,
    ) -> Result<DrainStats, (DrainStats, TransportError)> {
        let mut stats = DrainStats::default();
        let batch = pending.drain_batch(max_ops);
        let mut inflight: Vec<InFlight> = Vec::with_capacity(self.window);
        let mut iter = batch.into_iter();

        loop {
            // Fill the window.
            while inflight.len() < self.window {
                let Some((prefix, op)) = iter.next() else {
                    break;
                };
                match self.begin(prefix, &op, ledger, resolve, ports, transport, &mut stats) {
                    Ok(Begun::Sent {
                        context,
                        op: sent,
                        derived,
                    }) => inflight.push(InFlight {
                        context,
                        prefix,
                        sent,
                        original: op,
                        derived,
                    }),
                    // Nothing to send (withheld, unresolvable,
                    // out-of-family): already counted, ledger already
                    // updated.
                    Ok(Begun::Done) => {}
                    // `drain_batch` already removed this op, so
                    // "leave it pending" has to be an explicit
                    // requeue. Without it a route that arrives before
                    // its interface index does would vanish for good:
                    // absent from VPP, absent from the pending map,
                    // and absent from verification — a silent hole
                    // that nothing ever reports.
                    Ok(Begun::Defer) => pending.requeue(prefix, op),
                    // Parked, not dropped: the ledger keeps only the
                    // prefix and its Withheld state, so these nexthops
                    // are the only record of what the route should
                    // become when headroom returns.
                    Ok(Begun::Withhold) => pending.withhold(prefix, op),
                    Err(e) => {
                        self.unwind(pending, ledger, inflight, Some((prefix, op)), iter);
                        return Err((stats, e));
                    }
                }
            }
            if inflight.is_empty() {
                break;
            }

            // Read exactly one reply per request sent, recording
            // answers before applying any of them. Applying as we go
            // and bailing on the first error would strand the REST of
            // the window: their reservations would survive and they
            // would never be requeued — a silently partial FIB, which
            // is the failure this whole unwind path exists to prevent.
            let mut answered: Vec<i32> = Vec::with_capacity(inflight.len());
            let mut failure: Option<TransportError> = None;
            for f in inflight.iter() {
                match transport.recv::<IpRouteAddDelReply>() {
                    Ok((context, reply)) => {
                        // Contexts are issued in send order and VPP
                        // replies in order, so a mismatch means the
                        // stream desynchronised — not something to
                        // paper over by scanning ahead.
                        if context != f.context {
                            failure = Some(TransportError::ContextMismatch {
                                expected: f.context,
                                got: context,
                            });
                            break;
                        }
                        answered.push(reply.retval);
                    }
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }

            for (f, retval) in inflight.iter().zip(answered.iter()) {
                self.finish(f, *retval, pending, ledger, &mut stats);
            }

            if let Some(e) = failure {
                let unacked = inflight.split_off(answered.len());
                self.unwind(pending, ledger, unacked, None, iter);
                return Err((stats, e));
            }
            inflight.clear();
        }

        // Withdrawals during this drain may have freed slots. Release
        // parked ops so the NEXT drain retries them — releasing them
        // mid-drain would re-classify work we just parked in the same
        // pass. Gated on headroom so this cannot become a spin: with
        // no headroom nothing is released, and anything released that
        // still does not fit is simply parked again.
        if ledger.has_headroom() && pending.withheld_len() > 0 {
            stats.released = pending.release_withheld() as u64;
        }
        Ok(stats)
    }

    /// Classify and send one op. `Ok(None)` means there was nothing to
    /// send and the outcome is already recorded.
    #[allow(clippy::too_many_arguments)]
    fn begin(
        &self,
        prefix: IpPrefix,
        op: &PendingOp,
        ledger: &mut RouteLedger,
        resolve: &dyn Fn(&[IpAddr]) -> Vec<ResolvedPath>,
        ports: &PortIndex,
        transport: &mut Transport,
        stats: &mut DrainStats,
    ) -> Result<Begun, TransportError> {
        // Families VPP cannot be steered cannot benefit from a route
        // in its FIB. Dropping here (rather than requeueing) is
        // deliberate: the op was already removed from the pending map,
        // and requeueing something we will never send would grow that
        // map without bound.
        if !self.families.carries(prefix) {
            stats.out_of_family += 1;
            return Ok(Begun::Done);
        }
        match op {
            PendingOp::Upsert { nexthops } => {
                let resolved = resolve(nexthops);
                // Whether VPP currently holds a route for this prefix,
                // captured BEFORE classification overwrites the entry.
                let was_installed = matches!(
                    ledger.state_of(prefix),
                    Some(RouteState::Installed) | Some(RouteState::Installing { replacing: true })
                );

                // A live route whose nexthops all left VPP's ports.
                //
                // Withdrawn, not left alone: VPP is still forwarding the
                // PREVIOUS version, so leaving it keeps traffic on a path
                // the route source has abandoned.
                //
                // Sent BEFORE reclassifying, which is the subtle part.
                // Reclassifying first recorded `Unresolvable` immediately,
                // and that lost the prefix twice over: a *successful*
                // delete then hit `forget`, erasing the Unresolvable
                // state, so `verify` saw `unresolvable == 0`, never
                // sampled the prefix, and the supervisor could steer into
                // a table with a known hole; and a *rejected* delete left
                // the state Unresolvable, so the requeued upsert saw
                // `was_installed == false` and silently stopped retrying,
                // making a transient refusal permanent with the stale
                // route still live. Leaving the prefix `Installed` until
                // VPP confirms the delete fixes both: rejection retries,
                // success records the hole.
                if resolved.is_empty() && was_installed {
                    let ctx = transport.send(withdraw_msg(prefix))?;
                    return Ok(Begun::Sent {
                        context: ctx,
                        op: PendingOp::Withdraw,
                        derived: true,
                    });
                }

                // Ledger decides installable / withheld / unresolvable
                // and reserves the capacity slot. It takes the count
                // because we already resolved — running the mapping
                // policy twice per route is a million redundant passes
                // on a full-table load.
                let state = ledger.classify_resolved(prefix, resolved.len());
                match state {
                    RouteState::Installing { .. } => {}
                    RouteState::NotInstalled(nf) => {
                        match nf {
                            crate::sink::NotInstalled::Withheld => {
                                stats.withheld += 1;
                                return Ok(Begun::Withhold);
                            }
                            crate::sink::NotInstalled::Unresolvable => {
                                // Nothing live to withdraw — the
                                // was-installed case was handled above,
                                // before classification.
                                stats.unresolvable += 1;
                            }
                        }
                        return Ok(Begun::Done);
                    }
                    RouteState::Installed => return Ok(Begun::Done),
                }
                let Some(mut paths) = build_paths(&resolved, ports) else {
                    // Interface index not known yet: unwind the
                    // reservation and put it back rather than
                    // installing a route pointed at local0.
                    ledger.fail_install(prefix);
                    stats.deferred += 1;
                    return Ok(Begun::Defer);
                };
                if cap_paths(&mut paths) {
                    stats.paths_capped += 1;
                }
                let msg = IpRouteAddDel {
                    context: 0,
                    is_add: true,
                    is_multipath: false,
                    route: IpRoute {
                        table_id: 0,
                        stats_index: 0,
                        prefix: to_prefix(prefix),
                        // Cannot wrap: truncated above.
                        n_paths: paths.len() as u8,
                        paths,
                    },
                };
                Ok(Begun::Sent {
                    context: transport.send(msg)?,
                    op: PendingOp::Upsert {
                        nexthops: nexthops.clone(),
                    },
                    derived: false,
                })
            }
            // An authoritative withdrawal: the route source no longer
            // advertises this prefix at all.
            PendingOp::Withdraw => Ok(Begun::Sent {
                context: transport.send(withdraw_msg(prefix))?,
                op: PendingOp::Withdraw,
                derived: false,
            }),
        }
    }

    /// Apply VPP's answer to one op.
    fn finish(
        &self,
        f: &InFlight,
        retval: i32,
        pending: &mut PendingMap,
        ledger: &mut RouteLedger,
        stats: &mut DrainStats,
    ) {
        // Keyed on what was SENT, not on what was pending: an upsert
        // whose nexthops left VPP's ports goes out as a withdrawal,
        // and applying it as an install would record a route VPP just
        // deleted.
        match (&f.sent, retval) {
            (PendingOp::Upsert { .. }, 0) => {
                ledger.commit_installed(f.prefix);
                stats.installed += 1;
            }
            // Authoritative: the source dropped the prefix, so the
            // ledger should hold no opinion about it any more.
            (PendingOp::Withdraw, 0) if !f.derived => {
                ledger.forget(f.prefix);
                stats.withdrawn += 1;
            }
            // Derived: the prefix is still advertised, we simply cannot
            // reach any of its nexthops. The stale route is gone from
            // VPP — record the hole NOW, not before, so it survives into
            // verification. `forget` here would erase it and let the
            // supervisor steer traffic into a table it knows is
            // incomplete.
            (PendingOp::Withdraw, 0) => {
                ledger.classify_resolved(f.prefix, 0);
                stats.withdrawn += 1;
                stats.unresolvable += 1;
            }
            // A per-route rejection is NOT a connection fault: the
            // stream is fine and other routes will succeed. Unwind
            // this one and requeue it so a transient cause (a nexthop
            // whose interface is still coming up) resolves on retry
            // instead of leaving a hole nobody notices.
            _ => {
                ledger.fail_install(f.prefix);
                pending.requeue(f.prefix, f.original.clone());
                stats.rejected += 1;
            }
        }
    }

    /// Put back everything not positively acknowledged.
    fn unwind(
        &self,
        pending: &mut PendingMap,
        ledger: &mut RouteLedger,
        inflight: Vec<InFlight>,
        current: Option<(IpPrefix, PendingOp)>,
        rest: impl Iterator<Item = (IpPrefix, PendingOp)>,
    ) {
        for f in inflight {
            ledger.fail_install(f.prefix);
            // The ORIGINAL op, so a retry re-classifies from bird's
            // intent rather than replaying a withdrawal we derived
            // from resolution state that may since have changed back.
            pending.requeue(f.prefix, f.original);
        }
        if let Some((prefix, op)) = current {
            ledger.fail_install(prefix);
            pending.requeue(prefix, op);
        }
        for (prefix, op) in rest {
            pending.requeue(prefix, op);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::{Capacity, NexthopMap};
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [a, b, c, d],
            prefix_len: len,
        }
    }

    fn nh(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ports() -> PortIndex {
        let mut p = PortIndex::default();
        p.insert("eth3", None, 7);
        p.insert("eth2", None, 9);
        p.insert("eth3", Some(1337), 11);
        p
    }

    #[test]
    fn prefix_encodes_family_and_length() {
        let p = to_prefix(v4(198, 51, 100, 0, 24));
        assert_eq!(p.len, 24);
        assert_eq!(p.address.af, ADDRESS_IP4);
        assert_eq!(&p.address.un.0[..4], &[198, 51, 100, 0]);
        assert!(
            p.address.un.0[4..].iter().all(|&b| b == 0),
            "v4 must zero-fill the union tail"
        );
    }

    #[test]
    fn v6_prefix_uses_the_whole_union() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let p = to_prefix(IpPrefix::V6 {
            addr,
            prefix_len: 48,
        });
        assert_eq!(p.address.af, ADDRESS_IP6);
        assert_eq!(p.address.un.0, addr);
    }

    #[test]
    fn paths_carry_the_interface_index_and_nexthop() {
        let paths = build_paths(
            &[ResolvedPath {
                nexthop: nh(192, 0, 2, 1),
                target: NexthopTarget::Vf {
                    port: "eth3".into(),
                },
            }],
            &ports(),
        )
        .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].sw_if_index, 7);
        assert_eq!(paths[0].proto, FIB_API_PATH_NH_PROTO_IP4);
        assert_eq!(paths[0].r#type, FIB_API_PATH_TYPE_NORMAL);
        assert_eq!(paths[0].weight, 1);
        assert_eq!(&paths[0].nh.address.0[..4], &[192, 0, 2, 1]);
    }

    #[test]
    fn a_vlan_target_uses_the_subinterface_index_not_the_ports() {
        // Installing a VLAN route on the parent port's index would
        // send tagged traffic out untagged, which forwards to the
        // wrong place rather than failing.
        let paths = build_paths(
            &[ResolvedPath {
                nexthop: nh(192, 0, 2, 20),
                target: NexthopTarget::Subif {
                    port: "eth3".into(),
                    vlan: 1337,
                },
            }],
            &ports(),
        )
        .unwrap();
        assert_eq!(paths[0].sw_if_index, 11);
    }

    #[test]
    fn an_unknown_target_defers_rather_than_pointing_at_local0() {
        // sw_if_index 0 is local0. Encoding a route with a missing
        // index would install a black hole that looks installed.
        let out = build_paths(
            &[ResolvedPath {
                nexthop: nh(192, 0, 2, 1),
                target: NexthopTarget::Vf {
                    port: "eth9".into(),
                },
            }],
            &ports(),
        );
        assert!(out.is_none());
    }

    #[test]
    fn multipath_encodes_one_path_per_resolved_nexthop() {
        let paths = build_paths(
            &[
                ResolvedPath {
                    nexthop: nh(192, 0, 2, 1),
                    target: NexthopTarget::Vf {
                        port: "eth3".into(),
                    },
                },
                ResolvedPath {
                    nexthop: nh(192, 0, 2, 2),
                    target: NexthopTarget::Vf {
                        port: "eth2".into(),
                    },
                },
            ],
            &ports(),
        )
        .unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].sw_if_index, 7);
        assert_eq!(paths[1].sw_if_index, 9);
        assert!(
            paths.iter().all(|p| p.weight == 1 && p.preference == 0),
            "ECMP members share weight and tier"
        );
    }

    #[test]
    fn port_index_distinguishes_tagged_from_untagged() {
        let p = ports();
        assert_eq!(
            p.get(&NexthopTarget::Vf {
                port: "eth3".into()
            }),
            Some(7)
        );
        assert_eq!(
            p.get(&NexthopTarget::Subif {
                port: "eth3".into(),
                vlan: 1337
            }),
            Some(11)
        );
    }

    /// `n_paths` is a `u8` and the encoder writes `paths.len() as u8`
    /// independently of it, so an oversized set puts a wrapped count on
    /// the wire followed by more records than it declares.
    #[test]
    fn a_path_set_never_exceeds_what_the_wire_can_count() {
        let one = FibPath {
            sw_if_index: 3,
            table_id: 0,
            rpf_id: 0,
            weight: 1,
            preference: 0,
            r#type: 0,
            flags: 0,
            proto: 0,
            nh: Default::default(),
            n_labels: 0,
            label_stack: Default::default(),
        };

        // The realistic case is untouched: the reference fleet measured
        // ZERO ECMP groups, so this must not disturb ordinary routes.
        let mut small = vec![one.clone(); 4];
        assert!(!cap_paths(&mut small));
        assert_eq!(small.len(), 4);

        // Exactly at the limit still fits.
        let mut exact = vec![one.clone(); MAX_FIB_PATHS];
        assert!(!cap_paths(&mut exact));
        assert_eq!(exact.len(), MAX_FIB_PATHS);
        assert_eq!(exact.len() as u8 as usize, exact.len(), "no wrap");

        // One past it wraps to 0 without the cap — which is the whole
        // point: a declared count of 0 followed by 256 records.
        let mut over = vec![one; MAX_FIB_PATHS + 1];
        assert_eq!((MAX_FIB_PATHS + 1) as u8, 0, "this is the corruption");
        assert!(cap_paths(&mut over));
        assert_eq!(over.len(), MAX_FIB_PATHS);
        assert_eq!(over.len() as u8 as usize, over.len());
    }

    #[test]
    fn drain_stats_count_only_what_reached_vpp() {
        let s = DrainStats {
            installed: 3,
            withdrawn: 2,
            withheld: 5,
            unresolvable: 1,
            rejected: 1,
            deferred: 4,
            out_of_family: 7,
            released: 9,
            paths_capped: 0,
        };
        // Withheld/unresolvable/deferred/out-of-family never left the
        // process.
        assert_eq!(s.attempted(), 6);
    }

    #[test]
    fn a_nexthop_map_feeds_resolved_paths() {
        // The resolve closure the drainer takes is exactly the sink's
        // mapping policy, re-paired with the addresses the FIB needs.
        let mut m = NexthopMap::new(vec!["eth3".into()]);
        m.set_device(nh(192, 0, 2, 1), "eth3");
        m.set_device(nh(192, 0, 2, 9), "eth0"); // excluded
        let resolve = |nhs: &[IpAddr]| -> Vec<ResolvedPath> {
            nhs.iter()
                .filter_map(|ip| {
                    m.resolve(ip).map(|t| ResolvedPath {
                        nexthop: *ip,
                        target: t,
                    })
                })
                .collect()
        };
        let out = resolve(&[nh(192, 0, 2, 1), nh(192, 0, 2, 9)]);
        assert_eq!(out.len(), 1, "excluded devices drop out of the path set");
        assert_eq!(out[0].nexthop, nh(192, 0, 2, 1));

        let _ = RouteLedger::new(Capacity::new(10));
    }
}
