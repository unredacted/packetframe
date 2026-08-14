//! MCAM steering: the ntuple rules that divert allowlisted traffic to
//! VPP's VF, and the canary lever the rollout turns.
//!
//! ## What is being asked of the NIC
//!
//! One rule per (allowlisted prefix × direction). A packet whose source
//! *or* destination falls in the allowlist is redirected to the VF VPP
//! owns; everything else stays on the kernel path with the eBPF
//! fast-path in front of it. That asymmetry is the whole design: the
//! offload takes a slice of traffic and the fallback tier keeps the
//! rest, so a VPP that dies costs only the steered slice.
//!
//! ## The two details that are not guessable
//!
//! **`ring_cookie` is `(vf + 1) << 32`.** `ethtool`'s own `vf N`
//! keyword mis-encodes this on the rvu driver — gate 0a established the
//! raw form works and the keyword does not, by inserting both and
//! reading back what the NIC actually stored. Nothing about the uapi
//! documents it.
//!
//! **`loc` must be an allocated slot, and there are sixteen.** The
//! driver rejects an out-of-range location rather than assigning one, so
//! this module tracks the locations it owns and hands back exactly
//! those. The size comes from the NIC via `ETHTOOL_GRXCLSRLALL` — see
//! [`McamBudget::for_ifaces`] — because this file previously asserted it
//! instead, from `npc/mcam_info`'s "2048 entries, 1689 available". Those
//! figures are real and describe the NPC block across all six PFs; they
//! have never governed an ethtool `loc`, which on this hardware runs
//! `0..=15` per port. At two rules per prefix that is a ceiling of
//! **eight steerable IPv4 prefixes per port**, which is tight at
//! allowlist scale and is the opposite of what this paragraph used to
//! say.
//!
//! ## v4 only, by probe rather than by choice
//!
//! Gate 0b round 4: `ip6` ntuple insertion is rejected by the AF (error
//! 710) while the v4 control inserts cleanly — the vendor NPC profile
//! has no v6 extraction. So no IPv6 packet can be steered into VPP, and
//! a v6 prefix in the allowlist is skipped here rather than attempted.
//! [`crate::fib_sync::FamilyPolicy`] encodes the same verdict on the FIB
//! side; when a kernel bump makes v6 work, both flip together.
//!
//! ## What is here, and what is not
//!
//! This is the **policy** half only: which rules should exist, in which
//! slots, and what is refused. It touches no NIC, which is the point —
//! every mistake that silently misroutes traffic (a direction missed, a
//! family attempted that cannot work, a budget overrun leaving a port
//! half-steered) is decided here and tested without hardware.
//!
//! The ioctl half is [`crate::ntuple`], which installs what this plans
//! and reads every rule back with `ETHTOOL_GRXCLSRULE` before believing
//! it — `ethtool_rx_flow_spec` is not in `libc`, so its layout is
//! hand-written, and a field in the wrong place produces rules that
//! install cleanly and match the wrong traffic.

use std::net::Ipv4Addr;

use packetframe_common::config::VppSteerDirection;
use packetframe_common::fib::IpPrefix;

/// One steering rule, before it becomes bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SteerRule {
    /// The allowlisted prefix.
    pub prefix: Ipv4Addr,
    pub prefix_len: u8,
    /// Which side of the packet this rule matches.
    pub side: Side,
    /// MCAM slot. Assigned by [`RuleSet::plan`], not by the driver.
    pub location: u32,
    /// Where a match goes: into VPP, or back to the kernel.
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Src,
    Dst,
}

/// What a matching packet's fate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Redirect to VPP's VF — the steering rules proper.
    Divert,
    /// Deliver to the kernel (PF queue 0) — the exemptions, installed
    /// at HIGHER MCAM priority than any `Divert` rule so
    /// locally-terminating traffic never enters a dataplane that
    /// cannot deliver it.
    ///
    /// Why these exist, measured (w23, 2026-08-14): with `src`
    /// steering live, 110,917 packets in five minutes — the box's own
    /// service-monitoring replies, unicast DHCP renewals to the
    /// gateway, service-net→router management — matched the src rules
    /// and died at VPP's `null-node`, and 3,200 multicast frames
    /// (IGMP among them) were RPF-dropped instead of reaching the
    /// kernel bridge. The kernel is the only correct owner of that
    /// traffic; a `Keep` rule is how it stays there.
    ///
    /// `ring_cookie` 0 = PF queue 0 (`otx2_add_flow_msg`: a cookie
    /// with no VF bits becomes `NIX_RX_ACTIONOP_UCAST` toward the PF).
    /// One queue instead of RSS is an accepted cost for this traffic
    /// class — it is control-plane volume, not transit.
    Keep,
}

/// Exemptions every steered port carries regardless of config: IPv4
/// broadcast and multicast. Both are subnet-operational traffic the
/// kernel must see (DHCP DISCOVER answers, IGMP membership for the
/// bridge's snooping) and neither can ever be forwarded by VPP's
/// unicast FIB. Router-address exemptions are the operator's
/// (`steer-exempt`) because only the operator knows which addresses
/// terminate locally.
pub const BUILTIN_EXEMPTS: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(255, 255, 255, 255), 32),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
];

/// What steering *should* look like for a port, derived from the
/// allowlist.
///
/// Separated from the ioctl so the policy — which prefixes, which
/// directions, how many slots, what gets skipped — is decided and
/// tested without a NIC. Every mistake that silently misroutes traffic
/// lives in here rather than in the syscall.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleSet {
    pub rules: Vec<SteerRule>,
    /// v6 prefixes skipped because the NIC cannot match them. Reported
    /// rather than dropped: an operator whose allowlist is mostly v6
    /// should see that steering covers almost none of it.
    pub skipped_v6: u32,
}

/// Which MCAM slots a port may use, in the order they should be taken.
///
/// A budget rather than a constant because the NIC's table is shared —
/// UniFi's own rules live in it too — and overrunning it fails the
/// insert of whichever rule happens to be last, leaving a *partially*
/// steered port: some allowlisted traffic diverted to VPP, the rest on
/// the kernel path. That is not a degraded version of steering, it is a
/// different forwarding policy than either tier was configured for.
///
/// **A list of locations rather than a base and a count**, because the
/// previous shape could not express the two things that actually govern
/// it: which slots exist, and which are already taken. It carried
/// `base: 1024, count: 512`, reasoned from `npc/mcam_info` reporting
/// 2048 entries with 1689 available — figures that describe the NPC
/// block across all six PFs and have never governed an ethtool `loc`.
/// The real per-port space on this NIC is **0..=15**, so the first rule
/// the module ever tried to install was 1008 slots past the end and the
/// driver rejected it with `EINVAL`. See [`McamBudget::from_table`],
/// which asks the NIC instead of asserting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McamBudget {
    /// Locations this module may use, most-preferred first.
    pub free: Vec<u32>,
}

impl McamBudget {
    /// Take the free locations, highest first.
    ///
    /// Highest-first preserves the intent behind the old `base: 1024` —
    /// keep clear of whatever the vendor installs, without enumerating
    /// it, since the UniFi controller rewrites classifier state on every
    /// push. That reasoning was sound; only its arithmetic was wrong.
    /// Occupied slots are excluded outright rather than merely avoided,
    /// so a vendor rule appearing between `feasibility` and a steer
    /// costs a refusal instead of an overwrite.
    pub fn from_table(table: &crate::ntuple::RuleTable) -> Self {
        let free = (0..table.size)
            .rev()
            .filter(|loc| !table.occupied.contains(loc))
            .collect();
        Self { free }
    }

    /// The slots usable across *every* port that will steer.
    ///
    /// The intersection, not the first port's answer. One plan is
    /// installed on all of them at the same locations, so a slot free on
    /// eth4 and taken on eth5 is not a slot — and finding that out at
    /// insert time would leave a partially steered port, which is the
    /// one outcome [`RuleSet::plan`] exists to prevent.
    pub fn for_ifaces<'a>(ifaces: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut budget: Option<Self> = None;
        for iface in ifaces {
            let next = Self::from_table(&crate::ntuple::rule_table(iface)?);
            budget = Some(match budget {
                None => next,
                Some(prev) => Self {
                    free: prev
                        .free
                        .into_iter()
                        .filter(|loc| next.free.contains(loc))
                        .collect(),
                },
            });
        }
        // No steering ports means no NIC was asked and none will be
        // written; the caller is building a plan it will not install.
        Ok(budget.unwrap_or_default())
    }
}

impl Default for McamBudget {
    fn default() -> Self {
        // The measured size of an empty table on this NIC, used only
        // where there is no interface to ask — tests, and the non-Linux
        // stub. Every production path goes through `from_table`.
        Self {
            free: (0..crate::ntuple::FALLBACK_TABLE_SIZE).rev().collect(),
        }
    }
}

/// The sides a configured [`VppSteerDirection`] matches.
///
/// `both` is right for pure-transit deployments where VPP can forward
/// either direction of a flow. `src` is the service-edge shape:
/// outbound (src in the service prefix) rides VPP full-table best
/// path while inbound stays on the eBPF tier, whose FDB-pin owns
/// local delivery — dst-steering inbound service traffic would divert
/// it into a FIB with no path to the bridge-attached hosts it
/// terminates on. Split-tier flow halves are safe under the
/// stateless-transit invariant steering already requires.
pub fn sides_for(direction: VppSteerDirection) -> &'static [Side] {
    match direction {
        VppSteerDirection::Src => &[Side::Src],
        VppSteerDirection::Dst => &[Side::Dst],
        VppSteerDirection::Both => &[Side::Src, Side::Dst],
    }
}

/// How many prefixes in `allowlist` this NIC could steer at all.
///
/// v4 only: `ip6` ntuple is rejected by this NIC's AF, so a v6 prefix
/// consumes no slot and cannot be diverted.
///
/// A named function because two callers need the answer and one of them
/// needs it *before* touching a NIC: whether there is anything to steer
/// is a property of the config, and settling it first is what keeps an
/// unsteerable allowlist from being reported as an ioctl failure.
pub fn steerable_count(allowlist: &[IpPrefix]) -> usize {
    allowlist
        .iter()
        .filter(|p| matches!(p, IpPrefix::V4 { .. }))
        .count()
}

impl RuleSet {
    /// Decide the rules for one port: one per v4 prefix per configured
    /// side (see [`sides_for`] for what each direction means and when
    /// it is right).
    ///
    /// Fails rather than truncates when the budget cannot hold them all:
    /// a partially steered port forwards some allowlisted traffic
    /// through VPP and the rest through the kernel, which is a policy
    /// nobody chose.
    pub fn plan(
        allowlist: &[IpPrefix],
        exempts: &[packetframe_common::config::Ipv4Prefix],
        budget: McamBudget,
        direction: VppSteerDirection,
    ) -> Result<Self, String> {
        let sides = sides_for(direction);
        // Partition first, then check capacity, then build. The order is
        // what makes the refusal's numbers true: counting as we go can
        // only ever report how far we got, which is the budget size — the
        // one number the operator already knows.
        let steerable: Vec<(Ipv4Addr, u8)> = allowlist
            .iter()
            .filter_map(|p| match p {
                IpPrefix::V4 { addr, prefix_len } => Some((Ipv4Addr::from(*addr), *prefix_len)),
                IpPrefix::V6 { .. } => None,
            })
            .collect();
        let skipped_v6 = (allowlist.len() - steerable.len()) as u32;
        // Nothing to divert means nothing to exempt FROM — an all-v6
        // allowlist plans no rules at all rather than exemptions that
        // guard against a diversion that cannot happen.
        if steerable.is_empty() {
            return Ok(RuleSet {
                rules: Vec::new(),
                skipped_v6,
            });
        }
        let keeps: Vec<(Ipv4Addr, u8)> = BUILTIN_EXEMPTS
            .iter()
            .copied()
            .chain(exempts.iter().map(|p| (p.addr, p.prefix_len)))
            .collect();
        let diverts = steerable.len() * sides.len();
        let needed = diverts + keeps.len();

        if needed > budget.free.len() {
            return Err(format!(
                "steering needs {needed} MCAM rule(s) ({} steerable prefix(es) × {} \
                 direction(s), `steer-direction {direction}`, plus {} kernel exemption(s): \
                 2 built-in [broadcast, multicast] + {} `steer-exempt`) but only {} slot(s) \
                 are free on this NIC; steering part of the allowlist would split it across \
                 both forwarding tiers, so none is installed. The per-port ntuple table on \
                 this hardware holds 16 rules",
                steerable.len(),
                sides.len(),
                keeps.len(),
                exempts.len(),
                budget.free.len()
            ));
        }

        // Slot assignment carries the PRIORITY, so it is not free-form:
        // lower loc = lower MCAM entry index = matched first (v5.15
        // otx2_flows.c keeps flow_ent[] ascending and indexes it by
        // location). Divert rules take the budget's front (highest
        // locs, clear of vendor rules, as ever); Keep rules take the
        // BACK — the lowest free locs — so every exemption outranks
        // every diversion by construction. A `free` list sorted
        // highest-first makes front ≥ back unconditionally.
        let mut rules = Vec::with_capacity(needed);
        for (i, (addr, prefix_len)) in steerable.into_iter().enumerate() {
            for (j, side) in sides.iter().copied().enumerate() {
                rules.push(SteerRule {
                    prefix: addr,
                    prefix_len,
                    side,
                    location: budget.free[i * sides.len() + j],
                    action: RuleAction::Divert,
                });
            }
        }
        for (k, (addr, prefix_len)) in keeps.into_iter().enumerate() {
            rules.push(SteerRule {
                prefix: addr,
                prefix_len,
                side: Side::Dst,
                location: budget.free[budget.free.len() - 1 - k],
                action: RuleAction::Keep,
            });
        }
        Ok(RuleSet { rules, skipped_v6 })
    }

    /// The slots this set occupies, for the state file — teardown must
    /// remove exactly what was installed and nothing else.
    pub fn locations(&self) -> Vec<u32> {
        self.rules.iter().map(|r| r.location).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [a, b, c, d],
            prefix_len: len,
        }
    }

    /// Both directions, in slot order, with v6 counted rather than
    /// silently dropped.
    #[test]
    fn a_plan_covers_both_directions_and_reports_skipped_v6() {
        let allow = vec![
            v4(23, 191, 200, 0, 24),
            IpPrefix::V6 {
                addr: [0x26, 0x02, 0xf7, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 48,
            },
            v4(10, 88, 1, 0, 24),
        ];
        let set = RuleSet::plan(&allow, &[], McamBudget::default(), VppSteerDirection::Both)
            .expect("fits");

        assert_eq!(set.skipped_v6, 1, "the v6 prefix is reported, not hidden");
        assert_eq!(
            set.rules.len(),
            6,
            "two v4 prefixes x both directions, plus the two built-in exemptions"
        );
        assert_eq!(
            set.rules.iter().filter(|r| r.side == Side::Src).count(),
            2,
            "one source rule per v4 prefix"
        );
        let diverts: Vec<u32> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .map(|r| r.location)
            .collect();
        let keeps: Vec<u32> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| r.location)
            .collect();
        assert_eq!(
            diverts,
            vec![15, 14, 13, 12],
            "diversions take the highest free slots, clear of vendor rules, as ever"
        );
        assert_eq!(
            keeps,
            vec![0, 1],
            "exemptions take the LOWEST free slots — lower loc is higher MCAM priority, so \
             every exemption outranks every diversion"
        );
    }

    /// The two invariants the exemptions exist for: they outrank every
    /// diversion (lower slot = higher priority on this NIC), and the
    /// operator's `steer-exempt` entries ride alongside the built-ins.
    #[test]
    fn exemptions_outrank_diversions_and_include_the_operators() {
        use packetframe_common::config::Ipv4Prefix;
        let allow = vec![v4(23, 191, 200, 0, 24)];
        let exempts = vec![Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(23, 191, 200, 1),
            prefix_len: 32,
        }];
        let set = RuleSet::plan(
            &allow,
            &exempts,
            McamBudget::default(),
            VppSteerDirection::Src,
        )
        .expect("fits");
        let max_keep = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| r.location)
            .max()
            .expect("keeps exist");
        let min_divert = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .map(|r| r.location)
            .min()
            .expect("diverts exist");
        assert!(
            max_keep < min_divert,
            "every exemption must outrank every diversion: keep max {max_keep} vs divert \
             min {min_divert}"
        );
        // Built-ins + the operator's router address, all Keep, all Dst.
        let keep_prefixes: Vec<(std::net::Ipv4Addr, u8)> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| {
                assert_eq!(r.side, Side::Dst, "an exemption matches destinations");
                (r.prefix, r.prefix_len)
            })
            .collect();
        assert!(keep_prefixes.contains(&(std::net::Ipv4Addr::new(255, 255, 255, 255), 32)));
        assert!(keep_prefixes.contains(&(std::net::Ipv4Addr::new(224, 0, 0, 0), 4)));
        assert!(
            keep_prefixes.contains(&(std::net::Ipv4Addr::new(23, 191, 200, 1), 32)),
            "the operator's gateway exemption is the one that rescues DHCP renews and \
             monitoring replies (w23: 110,917 blackholed in five minutes without it)"
        );
    }

    /// An allowlist that does not fit installs NOTHING, and says how
    /// many rules it actually needed.
    ///
    /// The failure mode the refusal prevents is worse than no steering: a
    /// partially steered port forwards some allowlisted traffic through
    /// VPP and the rest through the kernel, a policy neither tier was
    /// configured for and which no counter names.
    ///
    /// The *number* is asserted because it is the number an operator
    /// sizes the budget from. Counting rules as they are built can only
    /// report how far the loop got — which is the budget size, the one
    /// figure they already have — so this asserts the true requirement
    /// and, explicitly, that the old understated figure is gone.
    #[test]
    fn an_allowlist_that_exceeds_the_budget_is_refused_whole() {
        let allow: Vec<IpPrefix> = (0..4).map(|i| v4(10, i, 0, 0, 16)).collect();
        let budget = McamBudget {
            free: (0..5).rev().collect(),
        };
        let e =
            RuleSet::plan(&allow, &[], budget, VppSteerDirection::Both).expect_err("must refuse");

        assert!(
            e.contains("needs 10 MCAM rule(s)"),
            "must name the TRUE requirement — diversions AND exemptions: {e}"
        );
        assert!(
            e.contains("2 built-in"),
            "the built-in exemptions are part of the arithmetic the operator sizes from: {e}"
        );
        assert!(
            e.contains("none is installed"),
            "the message must say the port is left unsteered: {e}"
        );

        // Enough slots and the same allowlist fits, so the refusal is
        // about the budget and not about the allowlist's shape.
        let ok = RuleSet::plan(
            &allow,
            &[],
            McamBudget {
                free: (0..10).rev().collect(),
            },
            VppSteerDirection::Both,
        )
        .expect("fits exactly");
        assert_eq!(ok.rules.len(), 10);
    }

    /// The refusal counts STEERABLE prefixes, not every line in the
    /// allowlist.
    ///
    /// A v6 prefix consumes no slot, so including it in the count would
    /// overstate the shortfall and send an operator looking for a budget
    /// increase they do not need — the inverse of the understatement
    /// above, and equally a number they would act on.
    #[test]
    fn the_refusal_does_not_count_prefixes_that_consume_no_slots() {
        let allow = vec![
            v4(10, 0, 0, 0, 16),
            v4(10, 1, 0, 0, 16),
            IpPrefix::V6 {
                addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 32,
            },
        ];
        let e = RuleSet::plan(
            &allow,
            &[],
            McamBudget {
                free: (0..3).rev().collect(),
            },
            VppSteerDirection::Both,
        )
        .expect_err("must refuse");
        assert!(
            e.contains("needs 6 MCAM rule(s)") && e.contains("2 steerable prefix(es)"),
            "the v6 prefix is not steerable and must not inflate either number: {e}"
        );
    }

    /// `steer-direction src` builds exactly one rule per prefix, all
    /// Src-side, at half the budget cost of `both` — the service-edge
    /// shape, where inbound stays on the eBPF tier because VPP has no
    /// path to the bridge-attached hosts it terminates on.
    #[test]
    fn src_only_builds_one_rule_per_prefix() {
        let allow = vec![v4(10, 0, 0, 0, 16), v4(10, 1, 0, 0, 16)];
        let set = RuleSet::plan(&allow, &[], McamBudget::default(), VppSteerDirection::Src)
            .expect("fits");
        assert_eq!(
            set.rules.len(),
            4,
            "2 src diverts + 2 built-in keeps: {:?}",
            set.rules
        );
        assert!(
            set.rules
                .iter()
                .filter(|r| r.action == RuleAction::Divert)
                .all(|r| r.side == Side::Src),
            "src-only must never DIVERT on a Dst match: {:?}",
            set.rules
        );

        let dst = RuleSet::plan(&allow, &[], McamBudget::default(), VppSteerDirection::Dst)
            .expect("fits");
        assert!(
            dst.rules
                .iter()
                .filter(|r| r.action == RuleAction::Divert)
                .all(|r| r.side == Side::Dst),
            "{:?}",
            dst.rules
        );

        // Half the divert rules means more prefixes fit: a budget that
        // refuses 2 prefixes under `both` takes them under `src`.
        let tight = McamBudget {
            free: (0..4).rev().collect(),
        };
        RuleSet::plan(&allow, &[], tight.clone(), VppSteerDirection::Both)
            .expect_err("four diverts + two keeps cannot fit four slots");
        let fits =
            RuleSet::plan(&allow, &[], tight, VppSteerDirection::Src).expect("fits src-only");
        assert_eq!(fits.rules.len(), 4);
    }

    /// The refusal names the configured direction, so an operator
    /// reading it knows which multiplier produced the number.
    #[test]
    fn the_refusal_names_the_direction() {
        let allow = vec![v4(10, 0, 0, 0, 16), v4(10, 1, 0, 0, 16)];
        let e = RuleSet::plan(
            &allow,
            &[],
            McamBudget { free: vec![15] },
            VppSteerDirection::Src,
        )
        .expect_err("must refuse");
        assert!(
            e.contains("1 direction(s)") && e.contains("steer-direction src"),
            "{e}"
        );
    }

    /// An allowlist with no v4 in it produces no rules and says why.
    #[test]
    fn a_v6_only_allowlist_produces_nothing_to_steer() {
        let allow = vec![IpPrefix::V6 {
            addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }];
        let set = RuleSet::plan(&allow, &[], McamBudget::default(), VppSteerDirection::Both)
            .expect("no rules is not an error");
        assert!(
            set.rules.is_empty(),
            "nothing to divert means nothing to exempt from — no keeps either: {:?}",
            set.rules
        );
        assert_eq!(
            set.skipped_v6, 1,
            "the operator has to be able to see that steering covers none of their allowlist"
        );
    }
}
