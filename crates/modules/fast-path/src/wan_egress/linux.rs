//! The netlink half of `wan-egress`: dump, write, and the reconcile
//! thread. Planning and the diff live in the parent module.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures::{StreamExt, TryStreamExt};
use netlink_packet_route::route::RouteProtocol;
use netlink_packet_route::rule::{RuleAction as NlAction, RuleAttribute, RuleFlags, RuleMessage};
use netlink_packet_route::AddressFamily;
use packetframe_common::config::Ipv4Prefix;
use packetframe_common::events::{kind, Event};
use rtnetlink::sys::{AsyncSocket, TokioSocket};
use rtnetlink::{Handle, IpVersion, MulticastGroup};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{
    desired_rules, diff, plan_layout, removal_stage, Condition, Layout, ObservedRule, OwnedRule,
    PlanError, RepairLimiter, RuleAction, Status, WanEgressSpec, LOCAL_TABLE, MAIN_TABLE,
    RECONCILE_INTERVAL,
};
use crate::netlink_bounds::NETLINK_EXCHANGE_TIMEOUT;
use crate::{MODULE_NAME, PACKETFRAME_RT_PROTOCOL};

/// How long after a rule event the pass runs. Folds a provisioning
/// burst (the platform rewrites its rules in groups) into one pass, and
/// the echo of our own writes into the same one.
const EVENT_DEBOUNCE: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum WanEgressError {
    #[error("netlink connection failed: {0}")]
    Connection(#[from] io::Error),
    #[error("netlink request failed: {0}")]
    Request(#[from] rtnetlink::Error),
    #[error("removed {removed} rules, then stopped: {first}")]
    Incomplete { removed: usize, first: String },
    #[error(
        "no netlink reply within {}s; abandoned where it stood",
        .0.as_secs()
    )]
    TimedOut(Duration),
}

/// A whole pass under [`NETLINK_EXCHANGE_TIMEOUT`]. A pass that never
/// returns holds the pass lock for good: the periodic pass stops and a
/// SIGHUP's reconcile waits on the lock forever. Abandoning one is safe
/// for the reason stopping at a failed write is: writes go out one at a
/// time in stage order, each awaited before the next, so a pass cut
/// short leaves an ordered prefix of them (the one in flight landed or
/// not), and the next pass, which starts from a fresh dump, does the rest.
async fn bounded<T>(
    pass: impl std::future::Future<Output = Result<T, WanEgressError>>,
) -> Result<T, WanEgressError> {
    tokio::time::timeout(NETLINK_EXCHANGE_TIMEOUT, pass)
        .await
        .unwrap_or(Err(WanEgressError::TimedOut(NETLINK_EXCHANGE_TIMEOUT)))
}

type StrictConnection =
    rtnetlink::proto::Connection<netlink_packet_route::RouteNetlinkMessage, TokioSocket>;

/// A netlink connection with `NETLINK_GET_STRICT_CHK` set, the pattern
/// neigh-snoop's `new_strict_connection()` and `fib::anyip` use: the
/// kernel then validates the dump request instead of quietly ignoring
/// whatever it does not understand. Duplicated rather than shared for
/// the reason `fib::anyip::strict_connection` gives.
fn strict_connection() -> io::Result<(StrictConnection, Handle)> {
    let (mut conn, handle, _) = rtnetlink::new_connection_with_socket::<TokioSocket>()?;
    conn.socket_mut()
        .socket_mut()
        .set_netlink_get_strict_chk(true)?;
    Ok((conn, handle))
}

/// The canonical prefix for a rule's address and length; `None` for
/// length 0, which is `all`.
fn prefix(addr: std::net::Ipv4Addr, len: u8) -> Option<Ipv4Prefix> {
    let raw = Ipv4Prefix {
        addr,
        prefix_len: len,
    };
    (len > 0).then(|| Ipv4Prefix {
        addr: raw.network(),
        prefix_len: len,
    })
}

/// An IPv4 rule as the planner sees it. `None` for any other family.
///
/// Every attribute outside the handful we write counts as a selector,
/// so neither `lookup main` detection nor ownership matching can be
/// fooled by a rule that only looks like one of those (an fwmark
/// `lookup main`, say, which a VPN daemon installs). The exceptions are
/// attributes the kernel sends for every rule whether set or not:
/// `FRA_SUPPRESS_PREFIXLEN` is emitted unconditionally, as -1 when
/// unset, and counting it made every rule, `lookup main` included, look
/// selected (the first qemu run of the netns test). `FRA_SUPPRESS_IFGROUP`
/// and `FRA_L3MDEV` get the same treatment at their unset values.
fn observe(m: &RuleMessage) -> Option<ObservedRule> {
    /// The kernel's -1, "not set", as the u32 the attribute carries.
    const UNSET: u32 = u32::MAX;
    if m.header.family != AddressFamily::Inet {
        return None;
    }
    let mut priority = 0;
    let mut table = u32::from(m.header.table);
    let mut goto = 0;
    let mut owned = false;
    let mut src = None;
    let mut dst = None;
    let mut other_selectors = m.header.tos != 0 || m.header.flags.contains(RuleFlags::Invert);
    for attr in &m.attributes {
        match attr {
            RuleAttribute::Priority(p) => priority = *p,
            RuleAttribute::Table(t) => table = *t,
            RuleAttribute::Goto(t) => goto = *t,
            RuleAttribute::Protocol(p) => owned = u8::from(*p) == PACKETFRAME_RT_PROTOCOL,
            RuleAttribute::Source(IpAddr::V4(a)) => src = prefix(*a, m.header.src_len),
            RuleAttribute::Destination(IpAddr::V4(a)) => dst = prefix(*a, m.header.dst_len),
            RuleAttribute::SuppressPrefixLen(UNSET)
            | RuleAttribute::SuppressIfGroup(UNSET)
            | RuleAttribute::L3MDev(false) => {}
            _ => other_selectors = true,
        }
    }
    let action = match m.header.action {
        NlAction::ToTable => RuleAction::ToTable(table),
        NlAction::Goto => RuleAction::Goto(goto),
        NlAction::Nop => RuleAction::Nop,
        _ => RuleAction::Other,
    };
    Some(ObservedRule {
        priority,
        action,
        src,
        dst,
        owned,
        other_selectors,
    })
}

fn message_for(rule: &OwnedRule) -> RuleMessage {
    let mut m = RuleMessage::default();
    m.header.family = AddressFamily::Inet;
    m.attributes.push(RuleAttribute::Priority(rule.priority()));
    m.attributes
        .push(RuleAttribute::Protocol(RouteProtocol::Other(
            PACKETFRAME_RT_PROTOCOL,
        )));
    fn from(m: &mut RuleMessage, p: &Ipv4Prefix) {
        m.header.src_len = p.prefix_len;
        m.attributes.push(RuleAttribute::Source(IpAddr::V4(p.addr)));
    }
    match rule {
        OwnedRule::Anchor { .. } => {
            m.header.action = NlAction::ToTable;
            m.header.table = LOCAL_TABLE as u8;
            m.attributes.push(RuleAttribute::Table(LOCAL_TABLE));
        }
        OwnedRule::Keep { src, dst, .. } => {
            m.header.action = NlAction::ToTable;
            m.header.table = MAIN_TABLE as u8;
            m.attributes.push(RuleAttribute::Table(MAIN_TABLE));
            from(&mut m, src);
            m.header.dst_len = dst.prefix_len;
            m.attributes
                .push(RuleAttribute::Destination(IpAddr::V4(dst.addr)));
        }
        OwnedRule::Goto { src, target, .. } => {
            m.header.action = NlAction::Goto;
            m.attributes.push(RuleAttribute::Goto(*target));
            from(&mut m, src);
        }
    }
    m
}

fn describe(r: &ObservedRule) -> String {
    match r.as_owned() {
        Some(o) => o.to_string(),
        None if r.is_legacy_anchor() => format!("{}: from all nop (legacy anchor)", r.priority),
        None => format!("{}: {:?} (unrecognised owned rule)", r.priority, r.action),
    }
}

/// Every IPv4 rule, the raw message beside what the planner sees. The
/// raw message is what a delete sends back: the kernel matches a
/// delete on every attribute it carries, so echoing the dumped rule
/// removes exactly that rule and nothing that merely resembles it.
async fn dump(handle: &Handle) -> Result<(Vec<RuleMessage>, Vec<ObservedRule>), WanEgressError> {
    let mut raw = Vec::new();
    let mut observed = Vec::new();
    let mut rules = handle.rule().get(IpVersion::V4).execute();
    while let Some(m) = rules.try_next().await? {
        if let Some(o) = observe(&m) {
            raw.push(m);
            observed.push(o);
        }
    }
    Ok((raw, observed))
}

async fn add(handle: &Handle, rule: &OwnedRule) -> Result<(), rtnetlink::Error> {
    let mut req = handle.rule().add();
    *req.message_mut() = message_for(rule);
    match req.execute().await {
        // NLM_F_EXCL: someone (a concurrent pass) got there first,
        // which is the state we wanted.
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::EEXIST => Ok(()),
        other => other,
    }
}

async fn delete(handle: &Handle, dumped: &RuleMessage) -> Result<(), rtnetlink::Error> {
    let mut m = dumped.clone();
    // Kernel-set state bits (unresolved goto, detached device) are
    // not selectors.
    m.header.flags = RuleFlags::empty();
    match handle.rule().del(m).execute().await {
        Err(rtnetlink::Error::NetlinkError(e))
            if e.raw_code() == -libc::ENOENT || e.raw_code() == -libc::ESRCH =>
        {
            Ok(())
        }
        other => other,
    }
}

/// What one pass saw and did.
#[derive(Debug, Clone)]
pub struct PassReport {
    /// `Err` means nothing was written.
    pub layout: Result<Layout, PlanError>,
    pub desired: usize,
    /// Desired rules in place when the pass finished.
    pub present: usize,
    pub added: Vec<OwnedRule>,
    pub removed: Vec<String>,
    /// One per failed write; the pass carries on past each.
    pub errors: Vec<String>,
}

impl PassReport {
    pub fn converged(&self) -> bool {
        self.layout.is_ok() && self.errors.is_empty()
    }

    pub fn wrote(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }
}

/// One reconcile: dump, plan, diff, write the difference. A converged
/// kernel gets a dump and nothing else. Bounded ([`bounded`]).
pub async fn reconcile_once(spec: &WanEgressSpec) -> Result<PassReport, WanEgressError> {
    bounded(reconcile_unbounded(spec)).await
}

async fn reconcile_unbounded(spec: &WanEgressSpec) -> Result<PassReport, WanEgressError> {
    let (conn, handle) = strict_connection()?;
    tokio::spawn(conn);
    let (raw, observed) = dump(&handle).await?;
    let layout = match plan_layout(&observed) {
        Ok(l) => l,
        Err(why) => {
            return Ok(PassReport {
                layout: Err(why),
                desired: spec.rule_count_without_anchor(),
                present: 0,
                added: Vec::new(),
                removed: Vec::new(),
                errors: Vec::new(),
            })
        }
    };
    let desired = desired_rules(spec, &layout);
    let d = diff(&desired, &observed);
    let mut report = PassReport {
        layout: Ok(layout),
        desired: desired.len(),
        present: d.present,
        added: Vec::new(),
        removed: Vec::new(),
        errors: Vec::new(),
    };
    // Writes are gated by stage, because a partial write can be worse
    // than none. Adds run anchor → keep → goto and stop at the first
    // stage with a failure: a goto without every keep rule of its
    // source would send kept destinations to the WAN. Removals run only
    // once every add has landed (the rules they remove may be the
    // working layout the adds were replacing) and stop the same way:
    // removing keep rules behind a goto whose removal failed would
    // leave that goto live without them. Whatever is left undone is
    // retried by the next pass.
    let mut failed_stage = None;
    for rule in &d.add {
        if failed_stage.is_some_and(|s| s != rule.stage()) {
            break;
        }
        match add(&handle, rule).await {
            Ok(()) => {
                report.present += 1;
                report.added.push(*rule);
            }
            Err(e) => {
                failed_stage = Some(rule.stage());
                report.errors.push(format!("add `{rule}`: {e}"));
            }
        }
    }
    if report.errors.is_empty() {
        let (removed, errors) = remove_staged(&handle, &raw, &observed, &d.remove).await;
        report.removed = removed;
        report.errors = errors;
    }
    Ok(report)
}

/// Delete the owned rules at `order` (removal order, see [`diff`]),
/// stopping after the first stage in which a delete failed. Returns
/// what was removed and one message per failure.
async fn remove_staged(
    handle: &Handle,
    raw: &[RuleMessage],
    observed: &[ObservedRule],
    order: &[usize],
) -> (Vec<String>, Vec<String>) {
    let mut removed = Vec::new();
    let mut errors = Vec::new();
    let mut failed_stage = None;
    for &i in order {
        let stage = removal_stage(&observed[i]);
        if failed_stage.is_some_and(|s| s != stage) {
            break;
        }
        let what = describe(&observed[i]);
        match delete(handle, &raw[i]).await {
            Ok(()) => removed.push(what),
            Err(e) => {
                failed_stage = Some(stage);
                errors.push(format!("remove `{what}`: {e}"));
            }
        }
    }
    (removed, errors)
}

/// Remove every rule wearing PacketFrame's protocol, anchor included:
/// gotos first, then keep rules, then the anchor, so no goto is ever
/// left pointing at nothing or live without its keep rules (a stage
/// with a failure ends the removal; see [`remove_staged`]). Foreign
/// rules are structurally out of reach: the delete echoes an owned
/// rule, protocol and all. Bounded ([`bounded`]).
pub async fn remove_all_owned() -> Result<usize, WanEgressError> {
    bounded(remove_all_owned_unbounded()).await
}

async fn remove_all_owned_unbounded() -> Result<usize, WanEgressError> {
    let (conn, handle) = strict_connection()?;
    tokio::spawn(conn);
    let (raw, observed) = dump(&handle).await?;
    let (removed, errors) =
        remove_staged(&handle, &raw, &observed, &diff(&[], &observed).remove).await;
    for r in &removed {
        info!(rule = %r, "wan-egress: rule removed");
    }
    match errors.first() {
        Some(e) => {
            for e in &errors {
                warn!(error = %e, "wan-egress: rule removal failed");
            }
            Err(WanEgressError::Incomplete {
                removed: removed.len(),
                first: e.clone(),
            })
        }
        None => Ok(removed.len()),
    }
}

/// [`remove_all_owned`] for callers without a runtime: `packetframe
/// detach`, and the attach path clearing leftovers when the directive
/// is absent.
pub fn remove_all_owned_blocking() -> Result<usize, WanEgressError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(remove_all_owned())
}

/// What a pass needs to remember about the ones before it.
#[derive(Default)]
struct PassMemory {
    /// The spec and layout of the last converged pass. A later pass
    /// that has to ADD rules under the same pair is a repair: rules
    /// disappeared while nothing about the config or the platform's
    /// rule layout changed.
    converged_on: Option<(WanEgressSpec, Layout)>,
    limiter: RepairLimiter,
}

struct Shared {
    /// `None` once the directive has left the config: passes then
    /// remove every owned rule until none remain (see
    /// [`WanEgress::retire`]).
    spec: Mutex<Option<WanEgressSpec>>,
    status: Mutex<Status>,
    /// Serializes passes between the thread and the synchronous
    /// callers (attach, SIGHUP). A tokio mutex because the thread
    /// holds it across the pass's awaits; it works across the two
    /// runtimes involved.
    pass: tokio::sync::Mutex<PassMemory>,
}

/// A pass for a retired spec: remove every owned rule. The caller
/// holds the pass lock.
async fn retire_pass(shared: &Shared, memory: &mut PassMemory) -> Result<usize, WanEgressError> {
    // Re-enabling the same spec later is a fresh install, not a repair.
    memory.converged_on = None;
    let result = remove_all_owned().await;
    let mut status = shared.status.lock().unwrap_or_else(PoisonError::into_inner);
    let condition = match &result {
        Ok(_) => Condition::Retired,
        Err(e) => Condition::Removing(e.to_string()),
    };
    if condition != status.condition {
        if let Condition::Removing(e) = &condition {
            warn!(error = %e, "wan-egress: rule removal incomplete; retrying every pass");
        }
    }
    // Retired is an observation (the removal finished): none remain. A
    // removal that stopped leaves an unknown number.
    let present = matches!(condition, Condition::Retired).then_some(0);
    *status = Status {
        condition,
        present,
        last_converged: status.last_converged,
        ..Status::default()
    };
    result
}

async fn run_pass(shared: &Shared) {
    let mut memory = shared.pass.lock().await;
    let spec = shared
        .spec
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some(spec) = spec else {
        let _ = retire_pass(shared, &mut memory).await;
        return;
    };
    let prev = shared
        .status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let now = Instant::now();
    let mut next = Status {
        last_converged: prev.last_converged,
        ..Status::default()
    };
    match reconcile_once(&spec).await {
        Err(e) => {
            next.condition = Condition::Failing(match e {
                // Abandoned anywhere in the pass, the dump included.
                WanEgressError::TimedOut(_) => e.to_string(),
                _ => format!("cannot read policy rules: {e}"),
            });
            next.desired = prev.desired;
            next.layout = prev.layout;
        }
        Ok(report) => {
            for r in &report.added {
                info!(rule = %r, "wan-egress: rule installed");
            }
            for r in &report.removed {
                info!(rule = %r, "wan-egress: rule removed");
            }
            next.desired = report.desired;
            next.present = Some(report.present);
            match report.layout {
                Err(why) => next.condition = Condition::Refused(why),
                Ok(layout) => {
                    next.layout = Some(layout);
                    let key = (spec, layout);
                    if !report.added.is_empty() && memory.converged_on.as_ref() == Some(&key) {
                        warn!(
                            added = report.added.len(),
                            removed = report.removed.len(),
                            "wan-egress: rules had disappeared under an unchanged config; \
                             repaired"
                        );
                        if let Some(suppressed) = memory.limiter.admit(now) {
                            Event::warn(MODULE_NAME, kind::WAN_EGRESS_REPAIRED)
                                .field("added", report.added.len())
                                .field("removed", report.removed.len())
                                .field("suppressed", suppressed)
                                .field("main_priority", layout.main)
                                .emit();
                        }
                    }
                    if report.errors.is_empty() {
                        next.condition = Condition::Converged;
                        next.last_converged = Some(now);
                        memory.converged_on = Some(key);
                    } else {
                        next.condition = Condition::Failing(report.errors.join("; "));
                    }
                }
            }
        }
    }
    // Refusals and failures repeat every pass; the journal hears about
    // each once, when the condition changes.
    if next.condition != prev.condition {
        match &next.condition {
            Condition::Converged => info!(
                rules = ?next.present,
                layout = ?next.layout,
                "wan-egress: policy rules in place"
            ),
            Condition::Refused(why) => warn!("wan-egress: {why}"),
            Condition::Failing(e) => warn!(error = %e, "wan-egress: repair failing"),
            Condition::Pending | Condition::Retired | Condition::Removing(_) => {}
        }
    }
    *shared.status.lock().unwrap_or_else(PoisonError::into_inner) = next;
}

fn run_pass_blocking(shared: &Shared) -> io::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_pass(shared));
    Ok(())
}

/// The periodic tick, rule events (debounced), and cancellation.
async fn watch(shared: Arc<Shared>, token: CancellationToken) {
    let mut tick = tokio::time::interval(RECONCILE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires at once; `start` has just run a pass.
    tick.tick().await;

    // Rule events make a repair prompt instead of up to one interval
    // late. Our own writes echo back here too, and cost one pass that
    // finds everything in place and writes nothing, so the echo cannot
    // feed itself. If the subscription fails the tick still covers it.
    let mut events = match rtnetlink::new_multicast_connection(&[MulticastGroup::Ipv4Rule]) {
        Ok((conn, handle, msgs)) => {
            tokio::spawn(conn);
            Some((handle, msgs))
        }
        Err(e) => {
            warn!(error = %e, "wan-egress: rule event subscription failed; periodic reconcile only");
            None
        }
    };
    let mut due: Option<tokio::time::Instant> = None;
    loop {
        let wake_at = due.unwrap_or_else(tokio::time::Instant::now);
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tick.tick() => run_pass(&shared).await,
            ev = async {
                match events.as_mut() {
                    Some((_, msgs)) => msgs.next().await,
                    None => std::future::pending().await,
                }
            } => match ev {
                // Any message, the overrun marker for lost events
                // included: what it said does not matter, because a pass
                // re-reads every rule.
                Some(_) => {
                    due.get_or_insert_with(|| tokio::time::Instant::now() + EVENT_DEBOUNCE);
                }
                None => {
                    warn!("wan-egress: rule event subscription closed; periodic reconcile only");
                    events = None;
                }
            },
            _ = tokio::time::sleep_until(wake_at), if due.is_some() => {
                due = None;
                run_pass(&shared).await;
            }
        }
    }
}

/// The running reconciler. Owned by the fast-path's `ActiveState`.
///
/// Dropping it (the preserve-attach exit) stops the thread and leaves
/// the rules in place, like the pinned programs: they serve the
/// kernel's forwarding path, which keeps running without the daemon,
/// and the next start adopts them by their protocol tag. `packetframe
/// detach` and [`Self::shutdown_and_remove`] take them out.
pub struct WanEgress {
    shared: Arc<Shared>,
    shutdown: CancellationToken,
    thread: Option<JoinHandle<()>>,
}

impl WanEgress {
    /// Run the first pass synchronously (so attach logs its outcome and
    /// `status` has a row from the start), then hand over to the
    /// reconcile thread. `Err` only when no runtime or thread can be
    /// created; netlink trouble is a degraded status, retried.
    pub fn start(spec: WanEgressSpec) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            spec: Mutex::new(Some(spec)),
            status: Mutex::new(Status::default()),
            pass: tokio::sync::Mutex::new(PassMemory::default()),
        });
        run_pass_blocking(&shared)?;
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let theirs = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("pf-wan-egress".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt.block_on(watch(theirs, token)),
                    Err(e) => warn!(
                        error = %e,
                        "wan-egress: runtime build failed; rules are reconciled only on SIGHUP"
                    ),
                }
            })?;
        Ok(Self {
            shared,
            shutdown,
            thread: Some(thread),
        })
    }

    /// A SIGHUP's spec: stored, then reconciled before returning, so
    /// the reload's outcome is in `status` when the reload is.
    pub fn set_spec(&self, spec: WanEgressSpec) -> io::Result<()> {
        *self
            .shared
            .spec
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(spec);
        run_pass_blocking(&self.shared)
    }

    /// The spec in force; `None` after [`Self::retire`].
    pub fn spec(&self) -> Option<WanEgressSpec> {
        self.shared
            .spec
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The directive has left the config: remove every owned rule now
    /// and report whether that finished. The reconciler keeps running
    /// either way, so a removal that did not finish stays on the
    /// status row and is retried by every pass (and by the next
    /// reload) instead of being forgotten; the caller drops the
    /// reconciler with [`Self::stop`] once this succeeds.
    pub fn retire(&self) -> Result<usize, WanEgressError> {
        *self
            .shared
            .spec
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut memory = self.shared.pass.lock().await;
                retire_pass(&self.shared, &mut memory).await
            })
    }

    /// Stop the thread, leaving the rules as they are.
    pub fn stop(mut self) {
        self.shutdown.cancel();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn status(&self) -> Status {
        self.shared
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Stop the thread, then remove every owned rule.
    pub fn shutdown_and_remove(self) -> Result<usize, WanEgressError> {
        self.stop();
        remove_all_owned_blocking()
    }
}

impl Drop for WanEgress {
    fn drop(&mut self) {
        // Rules stay (see the type's doc). Cancel without joining: a
        // pass in flight finishes on its own and the thread exits.
        self.shutdown.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wan_egress::OwnedRule;

    fn p(s: &str) -> Ipv4Prefix {
        s.parse().unwrap()
    }

    /// What we write is what we recognise as ours when it comes back:
    /// a rule built by `message_for` observes as exactly that rule.
    #[test]
    fn written_rules_round_trip_through_observe() {
        for rule in [
            OwnedRule::Anchor { priority: 32001 },
            OwnedRule::Keep {
                priority: 31998,
                src: p("198.18.0.0/24"),
                dst: p("10.0.0.0/8"),
            },
            OwnedRule::Goto {
                priority: 31999,
                src: p("198.18.0.0/24"),
                target: 32001,
            },
        ] {
            let mut dumped = message_for(&rule);
            // The kernel adds this to every rule it dumps.
            dumped
                .attributes
                .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
            let seen = observe(&dumped).expect("an IPv4 rule");
            assert!(seen.owned, "{rule}: protocol tag lost");
            assert_eq!(seen.as_owned(), Some(rule));
        }
    }

    /// UniFi's udapi-server aborts at start on any rule with neither a
    /// table nor a goto, so nothing we write may be one.
    #[test]
    fn every_written_rule_names_a_table_or_a_goto() {
        for rule in [
            OwnedRule::Anchor { priority: 32001 },
            OwnedRule::Keep {
                priority: 31998,
                src: p("198.18.0.0/24"),
                dst: p("10.0.0.0/8"),
            },
            OwnedRule::Goto {
                priority: 31999,
                src: p("198.18.0.0/24"),
                target: 32001,
            },
        ] {
            let m = message_for(&rule);
            let names_table = m.header.action == NlAction::ToTable
                && m.attributes
                    .iter()
                    .any(|a| matches!(a, RuleAttribute::Table(t) if *t != 0));
            let names_goto = m.header.action == NlAction::Goto
                && m.attributes
                    .iter()
                    .any(|a| matches!(a, RuleAttribute::Goto(_)));
            assert!(names_table || names_goto, "{rule}: {m:?}");
        }
    }

    #[test]
    fn a_legacy_nop_anchor_observes_as_one() {
        let mut m = RuleMessage::default();
        m.header.family = AddressFamily::Inet;
        m.header.action = NlAction::Nop;
        m.attributes = vec![
            RuleAttribute::Priority(32001),
            RuleAttribute::Protocol(RouteProtocol::Other(PACKETFRAME_RT_PROTOCOL)),
            RuleAttribute::SuppressPrefixLen(u32::MAX),
        ];
        let o = observe(&m).unwrap();
        assert!(o.is_legacy_anchor(), "{o:?}");
        assert_eq!(o.as_owned(), None, "replaced, not adopted");
        assert_eq!(describe(&o), "32001: from all nop (legacy anchor)");
    }

    #[test]
    fn foreign_and_selector_rules_are_not_ours_and_not_main() {
        let mut main = RuleMessage::default();
        main.header.family = AddressFamily::Inet;
        main.header.action = NlAction::ToTable;
        main.header.table = 254;
        // What the kernel dumps for `ip rule add pref 32000 lookup main`,
        // including the always-present suppress_prefixlength of -1.
        main.attributes = vec![
            RuleAttribute::Table(254),
            RuleAttribute::SuppressPrefixLen(u32::MAX),
            RuleAttribute::Protocol(RouteProtocol::Boot),
            RuleAttribute::Priority(32000),
        ];
        let o = observe(&main).unwrap();
        assert!(!o.owned && !o.other_selectors, "{o:?}");
        assert_eq!(crate::wan_egress::find_main(&[o]), Some(32000));

        // A real suppress_prefixlength (the wg-quick shape) is a selector.
        let mut suppress = main.clone();
        suppress.attributes[1] = RuleAttribute::SuppressPrefixLen(0);
        assert!(observe(&suppress).unwrap().other_selectors);

        let mut fwmark = main.clone();
        fwmark.attributes.push(RuleAttribute::FwMark(0x80000));
        let o = observe(&fwmark).unwrap();
        assert!(o.other_selectors);
        assert_eq!(crate::wan_egress::find_main(&[o]), None);

        let mut v6 = main;
        v6.header.family = AddressFamily::Inet6;
        assert!(observe(&v6).is_none());
    }
}
