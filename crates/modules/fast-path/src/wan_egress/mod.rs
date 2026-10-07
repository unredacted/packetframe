//! `wan-egress`: send traffic from chosen sources past the `main`
//! routing table, to the platform's own WAN policy and NAT.
//!
//! Some gateways run a full BGP table in the kernel's `main` table and
//! consult `main` (rule `lookup main`) *before* their own WAN policy
//! rules, while their NAT is masquerade on the WAN egress interfaces
//! only. A private source whose destination's best path is a peering
//! interface then follows `main` out that interface un-NATed and the
//! flow dies. The platform's own knobs cannot express "these sources
//! skip main", and hand-added rules do not survive its provisioning.
//!
//! The fix is three kinds of policy rule, all tagged with
//! [`crate::PACKETFRAME_RT_PROTOCOL`] as `FRA_PROTOCOL`:
//!
//! - **keep**: `from <src> to <keep> lookup main`, one per (source,
//!   keep) pair, so destinations that belong in `main` (private space,
//!   the operator's own prefixes) still resolve there;
//! - **goto**: `from <src> goto <main+1>`, one per source, at the
//!   priority just below `main`, jumping over it;
//! - **anchor**: `from all lookup local` at `main+1` when nothing else
//!   sits there. The kernel resolves a goto only to a rule that exists
//!   at its target priority (an unresolved goto is skipped, which would
//!   silently put the sources back in `main`), so the anchor guarantees
//!   a target whatever the platform does to the rules after `main`.
//!   It changes no lookup: `local` was already consulted at priority 0
//!   with the same key and missed, so it misses again and evaluation
//!   continues into the platform's own rules, exactly as from a `nop`.
//!   It is not a `nop` because UniFi's udapi-server refuses to start
//!   while any rule has neither a table nor a goto, and a `nop` anchor
//!   kept it down after a watchdog restart. Daemons before this change
//!   wrote the `nop`; a pass replaces it ([`ObservedRule::is_legacy_anchor`]).
//!
//! Ownership is the protocol tag: a rule wearing it is ours, adopted
//! from a previous daemon or repaired in place; a rule without it is
//! never modified or deleted, and a priority it occupies is never used.
//! Every pass dumps the IPv4 rules, plans the layout from the foreign
//! ones, diffs the desired set against the owned ones, and writes only
//! the difference, so a converged pass emits no `RTM_NEWRULE` /
//! `RTM_DELRULE` (other daemons on the box react to rule events).
//!
//! This file is the platform-independent half (spec, planning, diff,
//! status), unit-tested on every host. The netlink half and the
//! reconcile thread are in `linux.rs`.

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use packetframe_common::config::{Ipv4Prefix, ModuleDirective};
use packetframe_common::module::{HealthState, SubsystemHealth};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    reconcile_once, remove_all_owned, remove_all_owned_blocking, PassReport, WanEgress,
    WanEgressError,
};

/// The health row's name in `packetframe status`. Stable: dashboards
/// key on it.
pub const SUBSYSTEM_NAME: &str = "wan-egress";

/// The kernel's `main` routing table id.
pub const MAIN_TABLE: u32 = 254;

/// The kernel's `local` routing table id, which the anchor looks up.
pub const LOCAL_TABLE: u32 = 255;

/// How far below `main` the keep and goto rules may be placed when the
/// priorities right below it are taken by foreign rules.
pub const PRIORITY_BAND: u32 = 100;

/// How often the reconcile re-checks the rules with nothing prompting
/// it. The anyip route's cadence, for the same reason: a flushed rule
/// raises no error anywhere, so only time (or a rule event) notices.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Floor between two `wan_egress_repaired` events. Repairs in between
/// are counted into the next one.
pub const REPAIR_EVENT_INTERVAL: Duration = Duration::from_secs(300);

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Prefix {
    Ipv4Prefix {
        addr: Ipv4Addr::new(a, b, c, d),
        prefix_len: len,
    }
}

/// Destinations that stay in `main` for every wan-egress source,
/// before the config's own additions: RFC 1918, RFC 6598 shared
/// address space, and link-local. None of them is reachable through a
/// WAN, and all of them are how the gateway reaches its own networks.
pub const DEFAULT_KEEP: [Ipv4Prefix; 5] = [
    v4(10, 0, 0, 0, 8),
    v4(172, 16, 0, 0, 12),
    v4(192, 168, 0, 0, 16),
    v4(100, 64, 0, 0, 10),
    v4(169, 254, 0, 0, 16),
];

/// Why the fast-path is being torn down, as far as the wan-egress rules
/// care.
///
/// The rules serve kernel forwarding, which runs whether or not the XDP
/// datapath does. So only a teardown that means "PacketFrame is leaving
/// this box" removes them. A teardown on the way to a daemon that will
/// adopt them, or a stop of the XDP datapath for a reason unrelated to
/// routing policy, leaves them in place: removing them would reopen the
/// blackhole the rules exist to close, for as long as the box runs
/// without them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Teardown {
    /// `packetframe detach` / `detach --all`, or the module detached
    /// for any reason other than the circuit breaker.
    Full,
    /// `packetframe detach --keep-vpp`: the routine restart. The next
    /// daemon adopts the rules by their protocol tag.
    KeepVppRestart,
    /// The circuit breaker tripped. It stops XDP forwarding because
    /// XDP was dropping traffic; removing wan-egress too would send
    /// private sources back out the peering interface until an
    /// operator intervenes, the opposite of failing safe.
    BreakerTrip,
}

impl Teardown {
    pub fn removes_wan_egress_rules(self) -> bool {
        self == Self::Full
    }
}

/// The resolved directive: sources, and the full keep set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanEgressSpec {
    pub sources: Vec<Ipv4Prefix>,
    pub keep: Vec<Ipv4Prefix>,
}

impl WanEgressSpec {
    /// Rules the spec needs apart from the anchor, which depends on
    /// the kernel's rule set rather than on the spec.
    pub fn rule_count_without_anchor(&self) -> usize {
        self.sources.len() * (self.keep.len() + 1)
    }
}

/// The `wan-egress` directive resolved against the rest of the
/// section: the default keep set, every IPv4 `allow-prefix` and
/// `local-prefix`, and the explicit `keep` entries, normalized.
/// `None` when the section has no `wan-egress` line.
pub fn spec_from_directives(directives: &[ModuleDirective]) -> Option<WanEgressSpec> {
    let (sources, explicit_keep) = directives.iter().find_map(|d| match d {
        ModuleDirective::WanEgress { sources, keep, .. } => Some((sources, keep)),
        _ => None,
    })?;
    let mut keep: Vec<Ipv4Prefix> = DEFAULT_KEEP.to_vec();
    keep.extend(explicit_keep.iter().copied());
    for d in directives {
        match d {
            ModuleDirective::AllowPrefix4(p) => keep.push(*p),
            ModuleDirective::LocalPrefix { cidr, .. } => keep.push(*cidr),
            _ => {}
        }
    }
    Some(WanEgressSpec {
        sources: normalize(sources.iter().copied()),
        keep: normalize(keep),
    })
}

/// Canonical form of a prefix set: host bits cleared, duplicates
/// dropped, and any prefix inside another one dropped (both would
/// produce rules with the same effect), sorted by address.
pub fn normalize(prefixes: impl IntoIterator<Item = Ipv4Prefix>) -> Vec<Ipv4Prefix> {
    let mut all: Vec<Ipv4Prefix> = prefixes
        .into_iter()
        .map(|p| Ipv4Prefix {
            addr: p.network(),
            prefix_len: p.prefix_len,
        })
        .collect();
    // Shortest first, so a covering prefix is always seen before
    // anything it covers.
    all.sort_by_key(|p| (p.prefix_len, u32::from(p.addr)));
    let mut out: Vec<Ipv4Prefix> = Vec::new();
    for p in all {
        if !out.iter().any(|o| o.contains_prefix(&p)) {
            out.push(p);
        }
    }
    out.sort_by_key(|p| (u32::from(p.addr), p.prefix_len));
    out
}

/// What a policy rule does, as far as planning cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    ToTable(u32),
    Goto(u32),
    Nop,
    Other,
}

/// One IPv4 policy rule as the kernel reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRule {
    pub priority: u32,
    pub action: RuleAction,
    /// `None` is `from all`.
    pub src: Option<Ipv4Prefix>,
    /// `None` is `to all`.
    pub dst: Option<Ipv4Prefix>,
    /// Wears [`crate::PACKETFRAME_RT_PROTOCOL`].
    pub owned: bool,
    /// Any selector beyond src/dst (fwmark, iif/oif, tos, suppress_*,
    /// uid range, `not`, ...). A rule with one is neither the
    /// unconditional `lookup main` nor one of ours as we write them.
    pub other_selectors: bool,
}

impl ObservedRule {
    fn is_unconditional_main(&self) -> bool {
        !self.owned
            && !self.other_selectors
            && self.src.is_none()
            && self.dst.is_none()
            && self.action == RuleAction::ToTable(MAIN_TABLE)
    }

    /// The owned rule this observed rule is, when it is exactly one we
    /// would write.
    pub fn as_owned(&self) -> Option<OwnedRule> {
        if !self.owned || self.other_selectors {
            return None;
        }
        match (self.action, self.src, self.dst) {
            (RuleAction::ToTable(LOCAL_TABLE), None, None) => Some(OwnedRule::Anchor {
                priority: self.priority,
            }),
            (RuleAction::ToTable(MAIN_TABLE), Some(src), Some(dst)) => Some(OwnedRule::Keep {
                priority: self.priority,
                src,
                dst,
            }),
            (RuleAction::Goto(target), Some(src), None) => Some(OwnedRule::Goto {
                priority: self.priority,
                src,
                target,
            }),
            _ => None,
        }
    }

    /// The `nop` anchor daemons before the `lookup local` one wrote. It
    /// is not ours as we write rules now, so a pass removes it like any
    /// stale rule, after the new anchor is in: two rules then share
    /// `main+1`, and deleting the first moves every goto aimed at it to
    /// the second.
    pub fn is_legacy_anchor(&self) -> bool {
        self.owned
            && !self.other_selectors
            && self.action == RuleAction::Nop
            && self.src.is_none()
            && self.dst.is_none()
    }
}

/// A rule PacketFrame installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedRule {
    Anchor {
        priority: u32,
    },
    Keep {
        priority: u32,
        src: Ipv4Prefix,
        dst: Ipv4Prefix,
    },
    Goto {
        priority: u32,
        src: Ipv4Prefix,
        target: u32,
    },
}

impl OwnedRule {
    pub fn priority(&self) -> u32 {
        match *self {
            Self::Anchor { priority }
            | Self::Keep { priority, .. }
            | Self::Goto { priority, .. } => priority,
        }
    }

    /// Install order. The anchor goes first so every goto resolves the
    /// moment it lands, and keep before goto so no instant exists in
    /// which a source is sent past `main` without its keep set.
    /// Removal runs in the reverse order for the same reasons.
    fn stage(&self) -> u8 {
        match self {
            Self::Anchor { .. } => 0,
            Self::Keep { .. } => 1,
            Self::Goto { .. } => 2,
        }
    }
}

fn show(p: &Ipv4Prefix) -> String {
    format!("{}/{}", p.addr, p.prefix_len)
}

impl fmt::Display for OwnedRule {
    /// `ip rule` syntax, so a log line can be compared with
    /// `ip rule show` by eye.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor { priority } => write!(f, "{priority}: from all lookup local"),
            Self::Keep { priority, src, dst } => write!(
                f,
                "{priority}: from {} to {} lookup main",
                show(src),
                show(dst)
            ),
            Self::Goto {
                priority,
                src,
                target,
            } => write!(f, "{priority}: from {} goto {target}", show(src)),
        }
    }
}

/// Where the rules go, derived from the foreign rules alone, so the
/// answer does not move because of rules we installed ourselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Priority of the unconditional `lookup main`.
    pub main: u32,
    /// Priority of every keep rule.
    pub keep: u32,
    /// Priority of every goto rule.
    pub goto: u32,
    /// Where the gotos jump: always `main + 1`.
    pub target: u32,
    /// Whether the anchor is needed (nothing foreign at `target`).
    pub anchor: bool,
}

/// Why no layout exists. Either one means no writes this pass: the
/// rules already in place (ours included) are left exactly as they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// No unconditional `lookup main` rule: there is nothing to skip
    /// past, and nowhere to anchor the priorities.
    MainNotFound,
    /// Fewer than two free priorities between `low` and `main - 1`.
    BandExhausted { main: u32, low: u32 },
    /// `main` sits at the highest priority there is, so no rule can
    /// follow it.
    NoRoomAfterMain { main: u32 },
    /// A second unconditional `lookup main` follows the first. The
    /// goto resumes evaluation after the first, so the second would
    /// hand the sources straight back to the full table: installing
    /// would report healthy while changing nothing.
    SecondMain { first: u32, second: u32 },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MainNotFound => write!(
                f,
                "no unconditional `lookup main` rule found; refusing to install (there is \
                 nothing to skip past)"
            ),
            Self::BandExhausted { main, low } => write!(
                f,
                "priorities {low}..{} below main (at {main}) are taken by other rules; \
                 need two free ones, installing nothing and changing nothing",
                main - 1
            ),
            Self::NoRoomAfterMain { main } => write!(
                f,
                "main sits at priority {main}, the highest there is; no rule can follow it"
            ),
            Self::SecondMain { first, second } => write!(
                f,
                "a second unconditional `lookup main` at {second} follows the one at {first}; \
                 skipping the first would only reach the second, so nothing is installed or \
                 changed until one of them goes"
            ),
        }
    }
}

/// Priority of the unconditional `lookup main`, the lowest one if
/// there are several (that is where `main` is consulted first;
/// [`plan_layout`] refuses a layout with more than one).
pub fn find_main(observed: &[ObservedRule]) -> Option<u32> {
    observed
        .iter()
        .filter(|r| r.is_unconditional_main())
        .map(|r| r.priority)
        .min()
}

/// Plan the priorities.
///
/// The goto takes the nearest priority below `main` that no foreign
/// rule uses, the keep rules the nearest one below that, both within
/// [`PRIORITY_BAND`] of `main` (and never priority 0, the kernel's
/// `local` rule). A priority shared with a foreign rule is avoided
/// because the kernel orders same-priority rules by insertion time,
/// which the platform's next provisioning pass would change.
pub fn plan_layout(observed: &[ObservedRule]) -> Result<Layout, PlanError> {
    let main = find_main(observed).ok_or(PlanError::MainNotFound)?;
    if let Some(second) = observed
        .iter()
        .filter(|r| r.is_unconditional_main() && r.priority > main)
        .map(|r| r.priority)
        .min()
    {
        return Err(PlanError::SecondMain {
            first: main,
            second,
        });
    }
    let target = main
        .checked_add(1)
        .ok_or(PlanError::NoRoomAfterMain { main })?;
    let foreign: BTreeSet<u32> = observed
        .iter()
        .filter(|r| !r.owned)
        .map(|r| r.priority)
        .collect();
    let low = main.saturating_sub(PRIORITY_BAND).max(1);
    let free_below = |hi: u32| (low..hi).rev().find(|p| !foreign.contains(p));
    let exhausted = PlanError::BandExhausted { main, low };
    let goto = free_below(main).ok_or_else(|| exhausted.clone())?;
    let keep = free_below(goto).ok_or(exhausted)?;
    Ok(Layout {
        main,
        keep,
        goto,
        target,
        anchor: !foreign.contains(&target),
    })
}

/// Every rule the spec needs under `layout`, in install order.
pub fn desired_rules(spec: &WanEgressSpec, layout: &Layout) -> Vec<OwnedRule> {
    let mut out = Vec::with_capacity(spec.rule_count_without_anchor() + 1);
    if layout.anchor {
        out.push(OwnedRule::Anchor {
            priority: layout.target,
        });
    }
    for src in &spec.sources {
        for dst in &spec.keep {
            out.push(OwnedRule::Keep {
                priority: layout.keep,
                src: *src,
                dst: *dst,
            });
        }
    }
    for src in &spec.sources {
        out.push(OwnedRule::Goto {
            priority: layout.goto,
            src: *src,
            target: layout.target,
        });
    }
    out
}

/// What a pass has to write.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Diff {
    /// Missing rules, in install order.
    pub add: Vec<OwnedRule>,
    /// Indices into the observed slice of owned rules nothing desired
    /// matched (stale, duplicated, or altered), in removal order.
    pub remove: Vec<usize>,
    /// Desired rules already in place.
    pub present: usize,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }
}

/// Where an owned rule falls in removal order, which runs from the
/// highest stage down: unrecognised owned rules (3) first, then goto,
/// keep, anchor. A legacy `nop` anchor goes with the anchors, so a full
/// removal never leaves a goto without its target.
fn removal_stage(r: &ObservedRule) -> u8 {
    match r.as_owned() {
        Some(o) => o.stage(),
        None if r.is_legacy_anchor() => 0,
        None => 3,
    }
}

/// Desired against owned, as multisets: a duplicate of a desired rule
/// (the kernel accepts identical rules) is removed like any other
/// stale one. Foreign rules never appear in the result.
pub fn diff(desired: &[OwnedRule], observed: &[ObservedRule]) -> Diff {
    let mut unmatched: Vec<usize> = observed
        .iter()
        .enumerate()
        .filter(|(_, r)| r.owned)
        .map(|(i, _)| i)
        .collect();
    let mut add = Vec::new();
    let mut present = 0;
    for want in desired {
        match unmatched
            .iter()
            .position(|&i| observed[i].as_owned() == Some(*want))
        {
            Some(pos) => {
                unmatched.remove(pos);
                present += 1;
            }
            None => add.push(*want),
        }
    }
    add.sort_by_key(OwnedRule::stage);
    unmatched.sort_by_key(|&i| std::cmp::Reverse(removal_stage(&observed[i])));
    Diff {
        add,
        remove: unmatched,
        present,
    }
}

/// The outcome of the most recent pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// No pass has finished yet.
    Pending,
    /// Every desired rule is in place and nothing stale remains.
    Converged,
    /// No layout: nothing was written.
    Refused(PlanError),
    /// The dump or at least one write failed.
    Failing(String),
    /// The directive left the config and every owned rule is gone. A
    /// reload drops the reconciler as soon as it gets here, so this is
    /// seen only when a background pass finished a removal a reload
    /// could not.
    Retired,
    /// The directive left the config, but its rules could not all be
    /// removed yet; every pass retries.
    Removing(String),
}

/// What `status` and the metrics report.
#[derive(Debug, Clone)]
pub struct Status {
    pub condition: Condition,
    pub layout: Option<Layout>,
    pub desired: usize,
    pub present: usize,
    pub last_converged: Option<Instant>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            condition: Condition::Pending,
            layout: None,
            desired: 0,
            present: 0,
            last_converged: None,
        }
    }
}

impl Status {
    pub fn subsystem_health(&self, now: Instant) -> SubsystemHealth {
        let (state, message) = match &self.condition {
            Condition::Converged => {
                let placement = match &self.layout {
                    Some(l) => format!(
                        "; keep at {}, goto {} -> {} past main at {}{}",
                        l.keep,
                        l.goto,
                        l.target,
                        l.main,
                        if l.anchor { " (anchor)" } else { "" }
                    ),
                    None => String::new(),
                };
                (
                    HealthState::Healthy,
                    format!("{} rules in place{placement}", self.present),
                )
            }
            Condition::Pending => (
                HealthState::Degraded,
                "no reconcile has completed yet".to_string(),
            ),
            Condition::Refused(why) => (HealthState::Degraded, why.to_string()),
            Condition::Failing(error) => (
                HealthState::Degraded,
                format!(
                    "repair failing: {} of {} rules in place; {error}",
                    self.present, self.desired
                ),
            ),
            Condition::Retired => (
                HealthState::Healthy,
                "removed from the config; no rules remain".to_string(),
            ),
            Condition::Removing(error) => (
                HealthState::Degraded,
                format!(
                    "removed from the config, but its rules could not all be removed \
                     (retrying): {error}"
                ),
            ),
        };
        SubsystemHealth {
            name: SUBSYSTEM_NAME.to_string(),
            state,
            message: Some(message),
            last_success_age_seconds: self
                .last_converged
                .map(|t| now.saturating_duration_since(t).as_secs()),
        }
    }

    /// Textfile gauges: desired rules, the ones in place, and whether
    /// the last pass converged.
    pub fn render_metrics(&self, out: &mut String) {
        let healthy = u8::from(matches!(
            self.condition,
            Condition::Converged | Condition::Retired
        ));
        let _ = writeln!(
            out,
            "# HELP packetframe_wan_egress_rules wan-egress policy rules, desired and in place"
        );
        let _ = writeln!(out, "# TYPE packetframe_wan_egress_rules gauge");
        let _ = writeln!(
            out,
            "packetframe_wan_egress_rules{{module=\"fast-path\",state=\"desired\"}} {}",
            self.desired
        );
        let _ = writeln!(
            out,
            "packetframe_wan_egress_rules{{module=\"fast-path\",state=\"present\"}} {}",
            self.present
        );
        let _ = writeln!(
            out,
            "# HELP packetframe_wan_egress_converged 1 when the last wan-egress pass left every rule in place"
        );
        let _ = writeln!(out, "# TYPE packetframe_wan_egress_converged gauge");
        let _ = writeln!(
            out,
            "packetframe_wan_egress_converged{{module=\"fast-path\"}} {healthy}"
        );
    }
}

/// Rate limit for `wan_egress_repaired`: at most one event per
/// [`REPAIR_EVENT_INTERVAL`], carrying the count of the repairs it
/// swallowed since the last one.
#[derive(Debug, Default)]
pub struct RepairLimiter {
    last_emit: Option<Instant>,
    suppressed: u64,
}

impl RepairLimiter {
    /// `Some(suppressed)` when this repair should be recorded,
    /// `None` when it falls inside the window (and is counted).
    pub fn admit(&mut self, now: Instant) -> Option<u64> {
        match self.last_emit {
            Some(t) if now.saturating_duration_since(t) < REPAIR_EVENT_INTERVAL => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last_emit = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Ipv4Prefix {
        s.parse().unwrap()
    }

    fn parse(body: &str) -> Vec<ModuleDirective> {
        let cfg = packetframe_common::config::Config::parse(&format!("module fast-path\n{body}"))
            .expect("parse");
        cfg.modules[0].directives.clone()
    }

    fn foreign(priority: u32, action: RuleAction) -> ObservedRule {
        ObservedRule {
            priority,
            action,
            src: None,
            dst: None,
            owned: false,
            other_selectors: false,
        }
    }

    fn owned_from(r: &OwnedRule) -> ObservedRule {
        match *r {
            OwnedRule::Anchor { priority } => ObservedRule {
                priority,
                action: RuleAction::ToTable(LOCAL_TABLE),
                src: None,
                dst: None,
                owned: true,
                other_selectors: false,
            },
            OwnedRule::Keep { priority, src, dst } => ObservedRule {
                priority,
                action: RuleAction::ToTable(MAIN_TABLE),
                src: Some(src),
                dst: Some(dst),
                owned: true,
                other_selectors: false,
            },
            OwnedRule::Goto {
                priority,
                src,
                target,
            } => ObservedRule {
                priority,
                action: RuleAction::Goto(target),
                src: Some(src),
                dst: None,
                owned: true,
                other_selectors: false,
            },
        }
    }

    /// The platform shape: local at 0, main moved to 32000, WAN rules
    /// after it, and the kernel's default table rule.
    fn platform(main: u32) -> Vec<ObservedRule> {
        vec![
            foreign(0, RuleAction::ToTable(255)),
            foreign(main, RuleAction::ToTable(MAIN_TABLE)),
            foreign(32766, RuleAction::ToTable(201)),
            foreign(32767, RuleAction::ToTable(253)),
        ]
    }

    fn spec(sources: &[&str], keep: &[&str]) -> WanEgressSpec {
        WanEgressSpec {
            sources: sources.iter().map(|s| p(s)).collect(),
            keep: keep.iter().map(|s| p(s)).collect(),
        }
    }

    // --- teardown ---

    #[test]
    fn only_a_full_teardown_removes_the_rules() {
        assert!(Teardown::Full.removes_wan_egress_rules());
        assert!(
            !Teardown::KeepVppRestart.removes_wan_egress_rules(),
            "the routine restart: the next daemon adopts them"
        );
        assert!(
            !Teardown::BreakerTrip.removes_wan_egress_rules(),
            "the breaker stops XDP, not kernel routing policy"
        );
    }

    // --- spec ---

    #[test]
    fn no_directive_no_spec() {
        assert_eq!(
            spec_from_directives(&parse("  allow-prefix 198.51.100.0/24\n")),
            None
        );
    }

    #[test]
    fn default_keep_set_with_allow_and_local_prefixes() {
        let d = parse(
            "  allow-prefix 198.51.100.0/24\n  allow-prefix 10.20.0.0/16\n  \
             allow-prefix6 2001:db8::/32\n  local-prefix 203.0.113.0/26 via eth1\n  \
             wan-egress from 198.18.0.0/24 keep 192.0.2.0/25 keep 192.0.2.0/24\n",
        );
        let s = spec_from_directives(&d).unwrap();
        assert_eq!(s.sources, vec![p("198.18.0.0/24")]);
        assert_eq!(
            s.keep,
            vec![
                p("10.0.0.0/8"),
                p("100.64.0.0/10"),
                p("169.254.0.0/16"),
                p("172.16.0.0/12"),
                // 192.0.2.0/25 is inside the explicit /24.
                p("192.0.2.0/24"),
                p("192.168.0.0/16"),
                p("198.51.100.0/24"),
                p("203.0.113.0/26"),
            ],
            "defaults + allow-prefix + local-prefix + keep; 10.20/16 collapses into 10/8, \
             v6 is ignored"
        );
    }

    #[test]
    fn normalize_masks_dedupes_and_collapses() {
        let got = normalize([
            p("198.18.0.77/24"),
            p("198.18.0.0/24"),
            p("198.18.0.128/25"),
            p("192.0.2.0/24"),
        ]);
        assert_eq!(got, vec![p("192.0.2.0/24"), p("198.18.0.0/24")]);
    }

    // --- planning ---

    #[test]
    fn plan_on_a_moved_main() {
        let l = plan_layout(&platform(32000)).unwrap();
        assert_eq!(
            l,
            Layout {
                main: 32000,
                keep: 31998,
                goto: 31999,
                target: 32001,
                anchor: true,
            }
        );
    }

    #[test]
    fn plan_on_stock_linux_uses_the_default_rule_as_target() {
        // main at 32766, `default` at 32767: something already sits at
        // main+1, so no anchor.
        let rules = vec![
            foreign(0, RuleAction::ToTable(255)),
            foreign(32766, RuleAction::ToTable(MAIN_TABLE)),
            foreign(32767, RuleAction::ToTable(253)),
        ];
        let l = plan_layout(&rules).unwrap();
        assert_eq!(
            (l.main, l.goto, l.keep, l.target),
            (32766, 32765, 32764, 32767)
        );
        assert!(!l.anchor);
    }

    #[test]
    fn occupied_slots_move_down_to_the_nearest_free_priority() {
        let mut rules = platform(32000);
        rules.push(foreign(31999, RuleAction::ToTable(201)));
        rules.push(foreign(31997, RuleAction::ToTable(201)));
        let l = plan_layout(&rules).unwrap();
        assert_eq!((l.goto, l.keep), (31998, 31996));
    }

    #[test]
    fn our_own_rules_do_not_move_the_layout() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let base = platform(32000);
        let l = plan_layout(&base).unwrap();
        let mut with_ours = base.clone();
        with_ours.extend(desired_rules(&s, &l).iter().map(owned_from));
        assert_eq!(plan_layout(&with_ours).unwrap(), l);
    }

    #[test]
    fn band_exhaustion_is_refused() {
        let mut rules = platform(32000);
        // Everything from main-100 to main-1 but one priority.
        for pr in 31900..32000 {
            if pr != 31950 {
                rules.push(foreign(pr, RuleAction::ToTable(201)));
            }
        }
        assert_eq!(
            plan_layout(&rules),
            Err(PlanError::BandExhausted {
                main: 32000,
                low: 31900
            })
        );
        // Two free ones is enough, and they may be far apart.
        rules.retain(|r| r.priority != 31901);
        let l = plan_layout(&rules).unwrap();
        assert_eq!((l.goto, l.keep), (31950, 31901));
    }

    #[test]
    fn band_never_reaches_priority_zero() {
        let rules = vec![
            foreign(0, RuleAction::ToTable(255)),
            foreign(2, RuleAction::ToTable(MAIN_TABLE)),
        ];
        assert!(matches!(
            plan_layout(&rules),
            Err(PlanError::BandExhausted { main: 2, low: 1 })
        ));
    }

    #[test]
    fn missing_main_is_refused() {
        let rules = vec![
            foreign(0, RuleAction::ToTable(255)),
            foreign(32766, RuleAction::ToTable(201)),
        ];
        assert_eq!(plan_layout(&rules), Err(PlanError::MainNotFound));
    }

    #[test]
    fn a_second_unconditional_main_is_refused() {
        // Provisioning mid-way: the moved main is in, the stock one is
        // not gone yet. Skipping 32000 would land on 32766.
        let mut rules = platform(32000);
        rules.push(foreign(32766, RuleAction::ToTable(MAIN_TABLE)));
        assert_eq!(
            plan_layout(&rules),
            Err(PlanError::SecondMain {
                first: 32000,
                second: 32766
            })
        );
        // A selected main after it (a VPN daemon's fwmark rule) is not.
        let mut rules = platform(32000);
        let mut fwmark = foreign(32500, RuleAction::ToTable(MAIN_TABLE));
        fwmark.other_selectors = true;
        rules.push(fwmark);
        assert!(plan_layout(&rules).is_ok());
    }

    #[test]
    fn only_an_unconditional_foreign_rule_counts_as_main() {
        let mut fwmark = foreign(5210, RuleAction::ToTable(MAIN_TABLE));
        fwmark.other_selectors = true;
        let mut sourced = foreign(100, RuleAction::ToTable(MAIN_TABLE));
        sourced.src = Some(p("192.0.2.0/24"));
        let mut ours = foreign(50, RuleAction::ToTable(MAIN_TABLE));
        ours.owned = true;
        let mut rules = vec![fwmark, sourced, ours];
        assert_eq!(find_main(&rules), None);
        rules.push(foreign(32000, RuleAction::ToTable(MAIN_TABLE)));
        assert_eq!(find_main(&rules), Some(32000));
    }

    #[test]
    fn desired_rules_layout() {
        let s = spec(
            &["198.18.0.0/24", "198.18.1.0/24"],
            &["10.0.0.0/8", "192.0.2.0/24"],
        );
        let l = plan_layout(&platform(32000)).unwrap();
        let rules: Vec<String> = desired_rules(&s, &l)
            .iter()
            .map(|r| r.to_string())
            .collect();
        assert_eq!(
            rules,
            vec![
                "32001: from all lookup local",
                "31998: from 198.18.0.0/24 to 10.0.0.0/8 lookup main",
                "31998: from 198.18.0.0/24 to 192.0.2.0/24 lookup main",
                "31998: from 198.18.1.0/24 to 10.0.0.0/8 lookup main",
                "31998: from 198.18.1.0/24 to 192.0.2.0/24 lookup main",
                "31999: from 198.18.0.0/24 goto 32001",
                "31999: from 198.18.1.0/24 goto 32001",
            ]
        );
    }

    // --- diff ---

    #[test]
    fn fresh_install_adds_everything_in_order() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        let d = diff(&want, &obs);
        assert_eq!(d.present, 0);
        assert!(d.remove.is_empty());
        let stages: Vec<u8> = d.add.iter().map(OwnedRule::stage).collect();
        assert_eq!(stages, vec![0, 1, 2], "anchor, keep, goto");
    }

    #[test]
    fn converged_state_writes_nothing() {
        let s = spec(
            &["198.18.0.0/24", "198.18.1.0/24"],
            &["10.0.0.0/8", "192.0.2.0/24"],
        );
        let mut obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        obs.extend(want.iter().map(owned_from));
        // Re-plan against the full dump, as a pass does.
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        let d = diff(&want, &obs);
        assert!(d.is_empty(), "{d:?}");
        assert_eq!(d.present, want.len());
    }

    #[test]
    fn a_deleted_rule_is_the_only_thing_added_back() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8", "192.0.2.0/24"]);
        let mut obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        obs.extend(want.iter().map(owned_from));
        let gone = obs
            .iter()
            .position(|r| matches!(r.action, RuleAction::Goto(_)))
            .unwrap();
        obs.remove(gone);
        let d = diff(&want, &obs);
        assert_eq!(d.add.len(), 1);
        assert!(matches!(d.add[0], OwnedRule::Goto { .. }));
        assert!(d.remove.is_empty());
    }

    #[test]
    fn stale_duplicate_and_altered_owned_rules_are_removed_foreign_never() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let mut obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        obs.extend(want.iter().map(owned_from));
        // A duplicate goto, a keep for a destination no longer kept,
        // and an owned rule carrying a selector we never write.
        obs.push(owned_from(&want[2]));
        obs.push(owned_from(&OwnedRule::Keep {
            priority: 31998,
            src: p("198.18.0.0/24"),
            dst: p("192.0.2.0/24"),
        }));
        let mut marked = owned_from(&want[1]);
        marked.other_selectors = true;
        obs.push(marked);
        // A foreign rule identical to one of ours in every other way.
        let mut lookalike = owned_from(&want[1]);
        lookalike.owned = false;
        obs.push(lookalike);
        let d = diff(&want, &obs);
        assert!(d.add.is_empty(), "{d:?}");
        assert_eq!(d.remove.len(), 3, "{d:?}");
        for i in &d.remove {
            assert!(obs[*i].owned, "never a foreign rule");
        }
        // Unrecognised first, then goto before keep.
        assert!(obs[d.remove[0]].other_selectors);
        assert!(matches!(obs[d.remove[1]].action, RuleAction::Goto(_)));
        assert!(matches!(obs[d.remove[2]].action, RuleAction::ToTable(_)));
    }

    #[test]
    fn a_layout_move_adds_new_before_removing_old() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let mut obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        obs.extend(want.iter().map(owned_from));
        // The platform claims main-1.
        obs.push(foreign(31999, RuleAction::ToTable(201)));
        let l = plan_layout(&obs).unwrap();
        assert_eq!((l.goto, l.keep), (31998, 31997));
        let d = diff(&desired_rules(&s, &l), &obs);
        // Anchor unchanged; keep and goto re-placed.
        assert_eq!(d.present, 1);
        assert_eq!(d.add.len(), 2);
        assert_eq!(d.remove.len(), 2);
    }

    #[test]
    fn anchor_is_dropped_when_the_platform_fills_main_plus_one() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let mut obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        obs.extend(want.iter().map(owned_from));
        obs.push(foreign(32001, RuleAction::ToTable(201)));
        let l = plan_layout(&obs).unwrap();
        assert!(!l.anchor);
        let d = diff(&desired_rules(&s, &l), &obs);
        assert!(d.add.is_empty());
        assert_eq!(d.remove.len(), 1);
        assert_eq!(obs[d.remove[0]].action, RuleAction::ToTable(LOCAL_TABLE));
    }

    fn legacy_anchor(priority: u32) -> ObservedRule {
        ObservedRule {
            priority,
            action: RuleAction::Nop,
            src: None,
            dst: None,
            owned: true,
            other_selectors: false,
        }
    }

    #[test]
    fn a_legacy_nop_anchor_is_replaced_by_the_lookup_local_one() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let mut obs = platform(32000);
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        // What a daemon before the change left: keep and goto as now,
        // the anchor as a `nop`.
        obs.extend(
            want.iter()
                .filter(|r| !matches!(r, OwnedRule::Anchor { .. }))
                .map(owned_from),
        );
        obs.push(legacy_anchor(32001));
        let l = plan_layout(&obs).unwrap();
        assert!(l.anchor, "our own legacy anchor does not count as foreign");
        let d = diff(&desired_rules(&s, &l), &obs);
        assert_eq!(d.add, vec![OwnedRule::Anchor { priority: 32001 }]);
        assert_eq!(d.present, s.rule_count_without_anchor());
        assert_eq!(d.remove.len(), 1);
        assert!(obs[d.remove[0]].is_legacy_anchor());
    }

    #[test]
    fn a_full_removal_takes_a_legacy_anchor_last() {
        let s = spec(&["198.18.0.0/24"], &["10.0.0.0/8"]);
        let mut obs = platform(32000);
        obs.push(legacy_anchor(32001));
        let want = desired_rules(&s, &plan_layout(&obs).unwrap());
        obs.extend(
            want.iter()
                .filter(|r| !matches!(r, OwnedRule::Anchor { .. }))
                .map(owned_from),
        );
        let d = diff(&[], &obs);
        let order: Vec<RuleAction> = d.remove.iter().map(|&i| obs[i].action).collect();
        assert_eq!(
            order,
            vec![
                RuleAction::Goto(32001),
                RuleAction::ToTable(MAIN_TABLE),
                RuleAction::Nop
            ],
            "goto, keep, then the anchor it jumps to"
        );
    }

    #[test]
    fn the_platforms_own_local_rule_is_not_an_anchor() {
        // Priority 0 `lookup local` looks like the anchor but is foreign.
        assert_eq!(
            foreign(0, RuleAction::ToTable(LOCAL_TABLE)).as_owned(),
            None
        );
        assert!(!foreign(32001, RuleAction::Nop).is_legacy_anchor());
    }

    // --- status ---

    #[test]
    fn health_rows() {
        let now = Instant::now();
        let converged = Status {
            condition: Condition::Converged,
            layout: plan_layout(&platform(32000)).ok(),
            desired: 3,
            present: 3,
            last_converged: Some(now),
        };
        let h = converged.subsystem_health(now);
        assert_eq!(h.name, "wan-egress");
        assert_eq!(h.state, HealthState::Healthy);
        let msg = h.message.unwrap();
        assert!(msg.starts_with("3 rules in place"), "{msg}");
        assert!(
            msg.contains("past main at 32000") && msg.contains("(anchor)"),
            "{msg}"
        );

        let refused = Status {
            condition: Condition::Refused(PlanError::MainNotFound),
            ..Status::default()
        };
        let h = refused.subsystem_health(now);
        assert_eq!(h.state, HealthState::Degraded);
        assert!(h.message.unwrap().contains("lookup main"));

        let failing = Status {
            condition: Condition::Failing("EPERM".into()),
            desired: 3,
            present: 1,
            ..Status::default()
        };
        let h = failing.subsystem_health(now);
        assert_eq!(h.state, HealthState::Degraded);
        assert!(h.message.unwrap().contains("repair failing: 1 of 3"));

        assert_eq!(
            Status::default().subsystem_health(now).state,
            HealthState::Degraded,
            "silence must not read as healthy"
        );

        let removing = Status {
            condition: Condition::Removing("EBUSY".into()),
            ..Status::default()
        };
        let h = removing.subsystem_health(now);
        assert_eq!(h.state, HealthState::Degraded);
        assert!(h.message.unwrap().contains("could not all be removed"));
    }

    #[test]
    fn metrics_gauges() {
        let mut out = String::new();
        Status {
            condition: Condition::Converged,
            layout: None,
            desired: 7,
            present: 7,
            last_converged: None,
        }
        .render_metrics(&mut out);
        assert!(
            out.contains("packetframe_wan_egress_rules{module=\"fast-path\",state=\"desired\"} 7")
        );
        assert!(
            out.contains("packetframe_wan_egress_rules{module=\"fast-path\",state=\"present\"} 7")
        );
        assert!(out.contains("packetframe_wan_egress_converged{module=\"fast-path\"} 1"));
    }

    #[test]
    fn repair_events_are_rate_limited_and_count_what_they_swallow() {
        let t0 = Instant::now();
        let mut l = RepairLimiter::default();
        assert_eq!(l.admit(t0), Some(0));
        assert_eq!(l.admit(t0 + Duration::from_secs(10)), None);
        assert_eq!(l.admit(t0 + Duration::from_secs(20)), None);
        assert_eq!(l.admit(t0 + REPAIR_EVENT_INTERVAL), Some(2));
        assert_eq!(l.admit(t0 + REPAIR_EVENT_INTERVAL * 3), Some(0));
    }
}
