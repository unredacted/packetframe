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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Src,
    Dst,
}

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

/// Source and destination — see [`RuleSet::plan`] for why both.
const RULES_PER_PREFIX: usize = 2;

impl RuleSet {
    /// Decide the rules for one port.
    ///
    /// Two per v4 prefix, source and destination, because the allowlist
    /// names *networks we forward for* and traffic to them and from them
    /// are both ours. Steering only one direction would send a flow's
    /// two halves down different tiers, which is precisely the
    /// asymmetric-path case that breaks PMTUD and anything stateful
    /// downstream.
    ///
    /// Fails rather than truncates when the budget cannot hold them all:
    /// a partially steered port forwards some allowlisted traffic
    /// through VPP and the rest through the kernel, which is a policy
    /// nobody chose.
    pub fn plan(allowlist: &[IpPrefix], budget: McamBudget) -> Result<Self, String> {
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
        let needed = steerable.len() * RULES_PER_PREFIX;

        if needed > budget.free.len() {
            return Err(format!(
                "the allowlist needs {needed} MCAM rule(s) ({} steerable prefix(es) × {} \
                 directions) but only {} slot(s) are free on this NIC; steering part of the \
                 allowlist would split it across both forwarding tiers, so none is installed. \
                 The per-port ntuple table on this hardware holds 16 rules, so at two rules \
                 per prefix the allowlist can carry at most 8 IPv4 prefixes",
                steerable.len(),
                RULES_PER_PREFIX,
                budget.free.len()
            ));
        }

        let mut rules = Vec::with_capacity(needed);
        for (i, (addr, prefix_len)) in steerable.into_iter().enumerate() {
            for (j, side) in [Side::Src, Side::Dst].into_iter().enumerate() {
                rules.push(SteerRule {
                    prefix: addr,
                    prefix_len,
                    side,
                    location: budget.free[i * RULES_PER_PREFIX + j],
                });
            }
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
        let set = RuleSet::plan(&allow, McamBudget::default()).expect("fits");

        assert_eq!(set.skipped_v6, 1, "the v6 prefix is reported, not hidden");
        assert_eq!(set.rules.len(), 4, "two v4 prefixes, both directions");
        assert_eq!(
            set.rules.iter().filter(|r| r.side == Side::Src).count(),
            2,
            "one source rule per v4 prefix"
        );
        assert_eq!(
            set.locations(),
            vec![15, 14, 13, 12],
            "the highest free slots on a 16-entry table, consecutive so teardown can find them"
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
        let e = RuleSet::plan(&allow, budget).expect_err("must refuse");

        assert!(
            e.contains("needs 8 MCAM rule(s)"),
            "must name the TRUE requirement, not how far it got: {e}"
        );
        assert!(
            !e.contains("6 MCAM"),
            "reporting budget+1 tells the operator to try a size that also fails: {e}"
        );
        assert!(
            e.contains("none is installed"),
            "the message must say the port is left unsteered: {e}"
        );

        // One more slot and the same allowlist fits, so the refusal is
        // about the budget and not about the allowlist's shape.
        let ok = RuleSet::plan(
            &allow,
            McamBudget {
                free: (0..8).rev().collect(),
            },
        )
        .expect("fits exactly");
        assert_eq!(ok.rules.len(), 8);
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
            McamBudget {
                free: (0..3).rev().collect(),
            },
        )
        .expect_err("must refuse");
        assert!(
            e.contains("needs 4 MCAM rule(s)") && e.contains("2 steerable prefix(es)"),
            "the v6 prefix is not steerable and must not inflate either number: {e}"
        );
    }

    /// An allowlist with no v4 in it produces no rules and says why.
    #[test]
    fn a_v6_only_allowlist_produces_nothing_to_steer() {
        let allow = vec![IpPrefix::V6 {
            addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }];
        let set = RuleSet::plan(&allow, McamBudget::default()).expect("no rules is not an error");
        assert!(set.rules.is_empty());
        assert_eq!(
            set.skipped_v6, 1,
            "the operator has to be able to see that steering covers none of their allowlist"
        );
    }
}
