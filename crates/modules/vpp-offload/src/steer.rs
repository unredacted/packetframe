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
//! **`loc` must be an allocated slot.** The driver rejects an
//! out-of-range location rather than assigning one, so this module
//! tracks the locations it owns and hands back exactly those. The
//! reference NIC has 2048 MCAM entries with ~1689 free, so the budget
//! is real but not tight at allowlist scale.
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
//! The ioctl half is deliberately absent rather than sketched.
//! `ethtool_rx_flow_spec` is not in `libc`, so its layout would be
//! hand-written from a header this machine cannot read, and a field in
//! the wrong place produces rules that install cleanly and match the
//! wrong traffic. When it lands it must **read every rule back** with
//! `ETHTOOL_GRXCLSRULE` and compare against what was asked for, so the
//! layout is self-validating on the first real NIC instead of trusted —
//! the same reasoning the FIB readback verify rests on.

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

/// How many MCAM slots a port may use.
///
/// A budget rather than a constant because the NIC's table is shared —
/// UniFi's own rules live in it too — and overrunning it fails the
/// insert of whichever rule happens to be last, leaving a *partially*
/// steered port: some allowlisted traffic diverted to VPP, the rest on
/// the kernel path. That is not a degraded version of steering, it is a
/// different forwarding policy than either tier was configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McamBudget {
    /// First slot this module may use.
    pub base: u32,
    /// How many consecutive slots from `base`.
    pub count: u32,
}

impl Default for McamBudget {
    fn default() -> Self {
        // Measured on the reference NIC: 2048 entries, ~1689 free, and
        // UniFi's own rules sit low. Starting at 1024 keeps this module
        // clear of them without needing to enumerate what the vendor
        // installed — which changes under us on every controller push.
        Self {
            base: 1024,
            count: 512,
        }
    }
}

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
        let mut out = RuleSet::default();
        let mut next = budget.base;
        for p in allowlist {
            let (addr, prefix_len) = match p {
                IpPrefix::V4 { addr, prefix_len } => (Ipv4Addr::from(*addr), *prefix_len),
                IpPrefix::V6 { .. } => {
                    out.skipped_v6 += 1;
                    continue;
                }
            };
            for side in [Side::Src, Side::Dst] {
                if next >= budget.base + budget.count {
                    return Err(format!(
                        "allowlist needs more MCAM slots than the budget allows ({} rules for \
                         {} prefixes, budget {} from {}); steering part of the allowlist would \
                         split it across both forwarding tiers, so none is installed",
                        out.rules.len() + 1,
                        allowlist.len(),
                        budget.count,
                        budget.base
                    ));
                }
                out.rules.push(SteerRule {
                    prefix: addr,
                    prefix_len,
                    side,
                    location: next,
                });
                next += 1;
            }
        }
        Ok(out)
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
            vec![1024, 1025, 1026, 1027],
            "consecutive slots from the budget's base, so teardown can find them"
        );
    }

    /// An allowlist that does not fit installs NOTHING.
    ///
    /// The failure mode this prevents is worse than no steering: a
    /// partially steered port forwards some allowlisted traffic through
    /// VPP and the rest through the kernel, which is a forwarding policy
    /// neither tier was configured for and which no counter names.
    #[test]
    fn an_allowlist_that_exceeds_the_budget_is_refused_whole() {
        let allow: Vec<IpPrefix> = (0..4).map(|i| v4(10, i, 0, 0, 16)).collect();
        let budget = McamBudget { base: 0, count: 5 };
        let e = RuleSet::plan(&allow, budget).expect_err("must refuse");
        assert!(e.contains("MCAM slots"), "{e}");
        assert!(
            e.contains("none is installed"),
            "the message must say the port is left unsteered: {e}"
        );

        // One more slot and the same allowlist fits, so the refusal is
        // about the budget and not about the allowlist's shape.
        let ok = RuleSet::plan(&allow, McamBudget { base: 0, count: 8 }).expect("fits exactly");
        assert_eq!(ok.rules.len(), 8);
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
