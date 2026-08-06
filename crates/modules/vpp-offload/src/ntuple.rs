//! The ethtool half of MCAM steering: turning a [`crate::steer::RuleSet`]
//! into rules the NIC actually holds.
//!
//! [`crate::steer`] decides *what* should exist; this installs it and —
//! the part that matters — **reads every rule back and compares**.
//!
//! ## Why the readback is not optional
//!
//! `ethtool_rx_flow_spec` is not in `libc`, so its layout is written out
//! below from the uapi headers. A field in the wrong place does not
//! produce an error: the ioctl succeeds and the NIC holds a rule
//! matching something other than what was asked for. Traffic then
//! divides between the two forwarding tiers along a line nobody chose,
//! and every counter on both sides looks healthy.
//!
//! So [`insert`] issues `ETHTOOL_SRXCLSRLINS`, then `ETHTOOL_GRXCLSRULE`
//! for the same location, and refuses unless the addresses, masks,
//! ring_cookie and location all match. That makes the layout
//! self-validating the first time this runs on real hardware instead of
//! resting on arithmetic done from headers this codebase cannot compile
//! against. It is the same reasoning as the FIB readback verify, applied
//! to a struct definition rather than to a route.
//!
//! ## All-or-nothing
//!
//! [`NtupleSteering::steer`] removes everything it installed if any rule
//! fails. A partially steered port sends some allowlisted traffic to VPP
//! and the rest to the kernel — a third forwarding policy, one nobody
//! configured and no counter names. Refusing whole is the same rule
//! [`crate::steer::RuleSet::plan`] applies to the budget, enforced here
//! against the NIC rather than against arithmetic.

use crate::steer::{RuleSet, Side, SteerRule};

/// `ETHTOOL_SRXCLSRLINS` — insert a classifier rule.
const ETHTOOL_SRXCLSRLINS: u32 = 0x0000_0032;
/// `ETHTOOL_SRXCLSRLDEL` — delete one by location.
const ETHTOOL_SRXCLSRLDEL: u32 = 0x0000_0031;
/// `ETHTOOL_GRXCLSRULE` — read one back by location.
const ETHTOOL_GRXCLSRULE: u32 = 0x0000_002f;
/// `IP_USER_FLOW`: match IPv4 addresses irrespective of protocol.
///
/// The protocol-specific flow types would need one rule per protocol per
/// prefix, multiplying MCAM consumption to express a policy that does
/// not mention protocols at all.
const IP_USER_FLOW: u32 = 0x0d;

/// `ip_ver` within `ethtool_usrip4_spec` — after ip4src, ip4dst,
/// l4_4_bytes and tos.
const IP_VER_OFFSET: usize = 13;
/// `ETH_RX_NFC_IP4`, the value `ethtool` puts in `ip_ver`.
const ETH_RX_NFC_IP4: u8 = 1;

/// The table size assumed where there is no interface to ask.
///
/// Measured on the EFG's `rvu-nicpf` on 2026-08-05: locations 0..=15 are
/// accepted and 16 upward are rejected. Reached only by
/// [`crate::steer::McamBudget::default`] — tests and the non-Linux stub.
/// Production goes through [`rule_table`], because a constant is exactly
/// what put `base: 1024` in this file.
pub const FALLBACK_TABLE_SIZE: u32 = 16;

/// The `loc` space one interface actually offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTable {
    /// Locations run `0..size`. From the driver, not from us.
    pub size: u32,
    /// Locations already holding a rule — anyone's, not just ours.
    pub occupied: Vec<u32>,
}

/// Ask `iface` how big its ntuple table is and what already sits in it.
///
/// The one number that governs a `loc`, read from the thing that
/// enforces it. Note the failure mode this replaces is not a wrong
/// answer but a plausible one: `npc/mcam_info` reports a real, correct,
/// entirely different quantity, and nothing about reading it feels like
/// a guess.
pub fn rule_table(iface: &str) -> Result<RuleTable, String> {
    sys::rule_table(iface)
}

/// `union ethtool_flow_union` — sized by its `hdata[52]` member.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowUnion {
    hdata: [u8; 52],
}

/// `struct ethtool_flow_ext`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FlowExt {
    padding: [u8; 2],
    h_dest: [u8; 6],
    vlan_etype: u16,
    vlan_tci: u16,
    data: [u32; 2],
}

/// `struct ethtool_rx_flow_spec`.
///
/// The `ring_cookie` is `u64` and therefore forces 8-byte alignment,
/// which is where the padding between `m_ext` and it comes from. The
/// size assertion below records that arithmetic — but it only proves the
/// arithmetic is self-consistent, not that it matches the kernel, which
/// is what the readback is for.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RxFlowSpec {
    flow_type: u32,
    h_u: FlowUnion,
    h_ext: FlowExt,
    m_u: FlowUnion,
    m_ext: FlowExt,
    ring_cookie: u64,
    location: u32,
}

const _: () = assert!(core::mem::size_of::<FlowUnion>() == 52);
const _: () = assert!(core::mem::size_of::<FlowExt>() == 20);
const _: () = assert!(core::mem::size_of::<RxFlowSpec>() == 168);

/// `struct ethtool_rxnfc`, up to and including `rule_cnt`.
///
/// Enough for every command that names a single rule. `GRXCLSRLALL`
/// needs the trailing `rule_locs[]` as well and uses its own struct in
/// `sys`, because appending an array to this one lands it four bytes
/// past where the kernel writes.
///
/// Teardown still removes only the locations the ledger records — a slot
/// this module did not choose is one it cannot account for — so the
/// enumeration feeds slot *selection*, never removal.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rxnfc {
    cmd: u32,
    flow_type: u32,
    data: u64,
    fs: RxFlowSpec,
    rule_cnt: u32,
}

impl Default for FlowUnion {
    fn default() -> Self {
        Self { hdata: [0; 52] }
    }
}

/// `(vf + 1) << 32`, the raw `ring_cookie` that steers to a VF.
///
/// The `+ 1` is not an off-by-one: the PF's own queue 0 is cookie 0, so
/// VF indices are offset by one to keep 0 meaning "the PF". `ethtool`'s
/// `vf N` keyword encodes something else on this driver and the rule
/// silently lands on the wrong target — gate 0a established this by
/// inserting both forms and reading back what the NIC actually stored,
/// which is also why the readback here is not paranoia.
pub fn ring_cookie(vf_index: u32) -> u64 {
    (u64::from(vf_index) + 1) << 32
}

/// Netmask for a prefix length.
///
/// `0` and `32` are called out because the obvious `!0 << (32 - n)`
/// shifts a `u32` by 32 at `n == 0`, which panics in debug and is
/// undefined in release.
pub fn mask_for(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        n if n >= 32 => u32::MAX,
        n => u32::MAX << (32 - n),
    }
}

/// Build the flow spec for one rule. Split out so the encoding is
/// testable without a NIC — every field the NIC matches on is decided
/// here.
///
/// **A set bit in `m_u` means MATCH, and a zero means ignore** — so the
/// mask is the netmask itself and every field this rule does not name is
/// left at zero.
///
/// `ethtool -n` prints the OPPOSITE of what it stores. Its CLI `m`
/// argument means "bits to ignore", and it inverts on the way in and on
/// the way out, so a /24 the user typed as `m 0.0.0.255` displays as
/// `0.0.0.255` and sits in the struct as `ff ff ff 00`. Reading that
/// printed value as the stored one is how this function briefly grew an
/// all-ones default and a complemented mask, which asked the NIC to
/// match `proto == 0`, `tos == 0`, `ip_ver == 0`, the other address
/// against `0.0.0.0`, and 37 bytes of padding — rejected with
/// `EOPNOTSUPP`, on hardware, having been "fixed" from something that
/// was already right.
///
/// The bytes below are the ground truth, read back with `GRXCLSRULE`
/// from a rule `ethtool` inserted for source `23.191.200.0/24` to VF 0
/// on 2026-08-06:
///
/// ```text
/// flow_type  : 0d 00 00 00
/// h_u[0:16]  : 17 bf c8 00 00 00 00 00 00 00 00 00 00 01 00 00
/// m_u[0:16]  : ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00
/// ring_cookie: 00 00 00 00 01 00 00 00
/// ```
///
/// A decoded display is not the wire format. `GRXCLSRULE` was available
/// the whole time and would have settled it in one command.
fn flow_spec(rule: &SteerRule, vf_index: u32) -> RxFlowSpec {
    let mut fs = RxFlowSpec {
        flow_type: IP_USER_FLOW,
        ring_cookie: ring_cookie(vf_index),
        location: rule.location,
        ..RxFlowSpec::default()
    };
    // `ethtool_usrip4_spec` lays out as ip4src, ip4dst, l4_4_bytes, tos,
    // ip_ver, proto — so the two addresses are the first eight bytes of
    // the union, in network order.
    let addr = rule.prefix.octets();
    let mask = mask_for(rule.prefix_len).to_be_bytes();
    let (addr_off, mask_off) = match rule.side {
        Side::Src => (0, 0),
        Side::Dst => (4, 4),
    };
    fs.h_u.hdata[addr_off..addr_off + 4].copy_from_slice(&addr);
    fs.m_u.hdata[mask_off..mask_off + 4].copy_from_slice(&mask);
    // `ip_ver`, at offset 13. Its mask is zero, so the driver ignores the
    // value — this is here only because the one rule known to be accepted
    // by this NIC carries it, and matching a proven-good sample byte for
    // byte costs nothing.
    fs.h_u.hdata[IP_VER_OFFSET] = ETH_RX_NFC_IP4;
    fs
}

/// Whether a rule read back from the NIC is the one we asked it to hold.
///
/// Compares only what was set: a driver may normalise fields we left
/// zero, and failing on that would refuse a correctly installed rule.
/// What it must not tolerate is a difference in the four things that
/// decide behaviour — which addresses match, how much of them, and where
/// the packet goes.
fn matches(asked: &RxFlowSpec, got: &RxFlowSpec) -> bool {
    asked.flow_type == got.flow_type
        && asked.location == got.location
        && asked.ring_cookie == got.ring_cookie
        && asked.h_u.hdata[..8] == got.h_u.hdata[..8]
        && asked.m_u.hdata[..8] == got.m_u.hdata[..8]
}

#[cfg(all(target_os = "linux", not(test)))]
mod sys {
    use super::{RuleTable, RxFlowSpec, Rxnfc};

    /// `ETHTOOL_GRXCLSRLALL` — enumerate installed locations, and report
    /// how many the table holds. Lives here rather than beside the other
    /// command codes because it is the only one whose buffer is
    /// variable-length, and `RxnfcAll` below is why.
    const ETHTOOL_GRXCLSRLALL: u32 = 0x0000_0030;

    /// `ETHTOOL_GRXCLSRLCNT` — how many rules are installed.
    ///
    /// Not redundant with `GRXCLSRLALL`, and skipping it is a bug this
    /// module already shipped once: see [`rule_table`].
    const ETHTOOL_GRXCLSRLCNT: u32 = 0x0000_002e;

    /// The most locations one query will enumerate.
    ///
    /// Four times the measured table, so a NIC with a larger one is
    /// still describable; a driver reporting more rules than this fails
    /// loudly rather than returning a short list, which would make
    /// occupied slots look free.
    const MAX_ENUMERATED_RULES: usize = 64;

    /// `struct ethtool_rxnfc` **with its trailing `rule_locs[]`**.
    ///
    /// Written flat rather than as `{ Rxnfc, [u32; N] }` because that
    /// nesting is wrong in a way that compiles: `Rxnfc` ends on a `u32`
    /// at offset 184 but carries 8-byte alignment from its `data` field,
    /// so `size_of` rounds it to 192 and the array would start four
    /// bytes past where the kernel writes. The offset assertion below is
    /// the check, not the layout comment.
    #[repr(C)]
    struct RxnfcAll {
        cmd: u32,
        flow_type: u32,
        data: u64,
        fs: RxFlowSpec,
        rule_cnt: u32,
        rule_locs: [u32; MAX_ENUMERATED_RULES],
    }

    const _: () = assert!(core::mem::offset_of!(RxnfcAll, rule_locs) == 188);

    /// Two ioctls, and the first one is not optional.
    ///
    /// `rule_cnt` on the way IN is not "the size of my buffer" to this
    /// driver — it is *how many rules to go and find*. `otx2_get_all_flows`
    /// walks locations upward until it has collected that many, and
    /// `otx2_get_flow` returns `EINVAL` once `location >= max_flows`. So
    /// asking for a generous 64 on a table holding four rules walks off
    /// the end and returns that `EINVAL` as the result of the whole call.
    /// That is what this function did when it shipped, and it failed on
    /// the first box it ran against.
    ///
    /// `GRXCLSRLCNT` first, then ask for exactly that many — which is what
    /// `ethtool -n` does, and why `ethtool -n` worked throughout the
    /// session where this did not. With zero rules installed the second
    /// call requests zero, the driver's loop does not run, and `data`
    /// still comes back carrying the table size.
    pub(in crate::ntuple) fn rule_table(iface: &str) -> Result<RuleTable, String> {
        let mut cnt = Rxnfc {
            cmd: ETHTOOL_GRXCLSRLCNT,
            ..Rxnfc::default()
        };
        ethtool(iface, &mut cnt).map_err(|e| describe(iface, "counting ntuple rules", &e))?;
        let installed = cnt.rule_cnt as usize;
        if installed > MAX_ENUMERATED_RULES {
            return Err(format!(
                "{iface} holds {installed} ntuple rules, more than the {MAX_ENUMERATED_RULES} \
                 this can enumerate; refusing rather than reading a short list, which would \
                 make occupied slots look free and overwrite somebody else's rule"
            ));
        }

        let mut all = RxnfcAll {
            cmd: ETHTOOL_GRXCLSRLALL,
            flow_type: 0,
            data: 0,
            fs: RxFlowSpec::default(),
            // Exactly what exists. See the doc comment: to this driver
            // this is a target, not a capacity.
            rule_cnt: installed as u32,
            rule_locs: [0; MAX_ENUMERATED_RULES],
        };
        // SAFETY: the pointer covers the whole `RxnfcAll`, which is what
        // the kernel writes through for `GRXCLSRLALL`.
        unsafe { ethtool_raw(iface, (&mut all as *mut RxnfcAll).cast()) }
            .map_err(|e| describe(iface, "reading the ntuple rule table", &e))?;

        let count = (all.rule_cnt as usize).min(installed);
        Ok(RuleTable {
            size: all.data as u32,
            occupied: all.rule_locs[..count].to_vec(),
        })
    }

    /// Name the cause when the errno has a specific meaning here.
    ///
    /// The down-port hint is attached only to `EOPNOTSUPP`, because that
    /// is the only errno it explains — printed against the `EINVAL` above
    /// it sent a reader looking at link state for a malformed request.
    fn describe(iface: &str, what: &str, e: &std::io::Error) -> String {
        let hint = if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
            ". A port that is administratively DOWN answers this — `otx2_get_rxnfc` gates on \
             `netif_running` — which reads like the NIC lacks ntuple rather than like the link \
             being down. `ethtool -k` reports `ntuple-filters: on` either way and will not \
             disambiguate it; check `ip -br link`"
        } else {
            ""
        };
        format!("{what} of {iface}: {e}{hint}")
    }

    /// `SIOCETHTOOL`, the ioctl every ethtool command rides. Lives here
    /// rather than beside the `ETHTOOL_*` command codes because it is the
    /// only one that is a syscall number rather than a protocol constant,
    /// and the non-Linux stub has no use for it.
    const SIOCETHTOOL: u32 = 0x8946;

    /// One `SIOCETHTOOL` round trip against `iface`.
    ///
    /// # Safety
    /// `req` must be a fully initialised `Rxnfc` whose `cmd` names the
    /// operation; the kernel reads and writes through the pointer for
    /// the lifetime of the call only.
    pub(super) fn ethtool(iface: &str, req: &mut Rxnfc) -> Result<(), std::io::Error> {
        // SAFETY: the pointer covers a fully initialised `Rxnfc`, which
        // is the whole buffer for every command except `GRXCLSRLALL`.
        unsafe { ethtool_raw(iface, (req as *mut Rxnfc).cast()) }
    }

    /// # Safety
    /// `req` must point at a fully initialised `ethtool_rxnfc`-shaped
    /// buffer large enough for whatever its `cmd` makes the kernel write
    /// — for `GRXCLSRLALL` that includes the trailing `rule_locs[]`.
    unsafe fn ethtool_raw(iface: &str, req: *mut core::ffi::c_void) -> Result<(), std::io::Error> {
        let name = iface.as_bytes();
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        if name.len() >= ifr.ifr_name.len() {
            return Err(std::io::Error::other(format!(
                "interface name `{iface}` exceeds IFNAMSIZ"
            )));
        }
        for (dst, src) in ifr.ifr_name.iter_mut().zip(name) {
            *dst = *src as libc::c_char;
        }
        ifr.ifr_ifru.ifru_data = req as *mut libc::c_char;

        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // `ioctl`'s request argument is `c_ulong` on glibc and `c_int`
        // on musl, so this cast is a no-op on one published target and
        // load-bearing on another — the same reason `probe/mod.rs` and
        // `probe/bpf.rs` carry this allow. Without it clippy fails the
        // glibc build; without the cast, the musl build does not compile.
        #[allow(clippy::unnecessary_cast)]
        let rc = unsafe { libc::ioctl(sock, SIOCETHTOOL as _, &mut ifr) };
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock) };
        if rc != 0 {
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(all(not(target_os = "linux"), not(test)))]
mod sys {
    use super::{RuleTable, Rxnfc};
    pub(super) fn ethtool(_iface: &str, _req: &mut Rxnfc) -> Result<(), std::io::Error> {
        Err(std::io::Error::other("ntuple steering is Linux-only"))
    }
    pub(in crate::ntuple) fn rule_table(_iface: &str) -> Result<RuleTable, String> {
        Err("ntuple steering is Linux-only".into())
    }
}

/// An in-memory NIC standing in for `SIOCETHTOOL`, tests only.
///
/// Exists because without it **nothing in [`NtupleSteering::steer`] or
/// [`NtupleSteering::unsteer`] had ever executed** — every `ethtool`
/// call fails on a dev host and fails for a different reason on a CI
/// runner with no such interface, so both routines could only ever be
/// tested along their failure paths. The sequencing they encode
/// (reconcile stale rules before installing, all-or-nothing rollback,
/// a ledger that is a set) is exactly what a failure-only test cannot
/// see.
///
/// **What this does NOT prove**: the wire format. The fake stores
/// whatever `flow_spec` produced and hands the same bytes back, so a
/// field at the wrong offset round-trips perfectly here. That check has
/// one real venue — the `ETHTOOL_GRXCLSRULE` readback against a real
/// NIC — and it is still unrun. This substitutes for a NIC's
/// *behaviour*, not for its *layout*.
#[cfg(test)]
pub(super) mod sys {
    use super::{Rxnfc, ETHTOOL_GRXCLSRULE, ETHTOOL_SRXCLSRLDEL, ETHTOOL_SRXCLSRLINS};
    use std::cell::RefCell;
    use std::collections::HashMap;

    pub(crate) struct FakeNic {
        rules: HashMap<(String, u32), super::RxFlowSpec>,
        /// Locations whose delete must fail, modelling the rule that
        /// will not come out — the case the release rules turn on.
        undeletable: Vec<u32>,
        /// Locations whose insert must fail, modelling a full or
        /// otherwise refusing MCAM.
        uninsertable: Vec<u32>,
        /// How many locations this fake offers. Defaults to the measured
        /// hardware size rather than to zero, so a test that forgets to
        /// set it gets a plausible NIC instead of one with no table.
        table_size: u32,
    }

    impl Default for FakeNic {
        fn default() -> Self {
            Self {
                rules: HashMap::new(),
                undeletable: Vec::new(),
                uninsertable: Vec::new(),
                table_size: super::FALLBACK_TABLE_SIZE,
            }
        }
    }

    thread_local! {
        static NIC: RefCell<FakeNic> = RefCell::new(FakeNic::default());
    }

    /// Start from an empty NIC. Call at the top of any test that
    /// installs rules; the state is per-thread, and Rust runs each test
    /// on its own.
    pub(crate) fn reset() {
        NIC.with(|n| *n.borrow_mut() = FakeNic::default());
    }

    pub(crate) fn wedge_delete(locations: &[u32]) {
        NIC.with(|n| n.borrow_mut().undeletable = locations.to_vec());
    }

    pub(crate) fn wedge_insert(locations: &[u32]) {
        NIC.with(|n| n.borrow_mut().uninsertable = locations.to_vec());
    }

    pub(crate) fn set_table_size(size: u32) {
        NIC.with(|n| n.borrow_mut().table_size = size);
    }

    /// The fake's answer to `GRXCLSRLALL`.
    ///
    /// Note what this cannot stand in for: the real one reads a size the
    /// *driver* chose, and the whole defect it exists to prevent was a
    /// number this codebase chose for itself. A test using this proves
    /// the budget arithmetic, never the size.
    pub(in crate::ntuple) fn rule_table(iface: &str) -> Result<super::RuleTable, String> {
        NIC.with(|n| {
            let nic = n.borrow();
            let mut occupied: Vec<u32> = nic
                .rules
                .keys()
                .filter(|(i, _)| i == iface)
                .map(|(_, loc)| *loc)
                .collect();
            occupied.sort_unstable();
            Ok(super::RuleTable {
                size: nic.table_size,
                occupied,
            })
        })
    }

    /// Every `(iface, loc)` the NIC currently holds, sorted — the
    /// ground truth a test compares the ledger against.
    pub(crate) fn rules() -> Vec<(String, u32)> {
        NIC.with(|n| {
            let mut v: Vec<(String, u32)> = n.borrow().rules.keys().cloned().collect();
            v.sort();
            v
        })
    }

    pub(super) fn ethtool(iface: &str, req: &mut Rxnfc) -> Result<(), std::io::Error> {
        NIC.with(|n| {
            let mut nic = n.borrow_mut();
            let key = (iface.to_string(), req.fs.location);
            match req.cmd {
                ETHTOOL_SRXCLSRLINS => {
                    if nic.uninsertable.contains(&req.fs.location) {
                        return Err(std::io::Error::other("ENOSPC: no free MCAM entry"));
                    }
                    // A real insert at an occupied slot replaces it,
                    // which is what makes re-asserting cheap.
                    nic.rules.insert(key, req.fs);
                    Ok(())
                }
                ETHTOOL_GRXCLSRULE => match nic.rules.get(&key) {
                    Some(stored) => {
                        req.fs = *stored;
                        Ok(())
                    }
                    None => Err(std::io::Error::other("ENOENT: no rule at that location")),
                },
                ETHTOOL_SRXCLSRLDEL => {
                    if nic.undeletable.contains(&req.fs.location) {
                        return Err(std::io::Error::other("EBUSY: rule is pinned"));
                    }
                    match nic.rules.remove(&key) {
                        Some(_) => Ok(()),
                        None => Err(std::io::Error::other("ENOENT: no rule at that location")),
                    }
                }
                other => Err(std::io::Error::other(format!(
                    "fake NIC got an unexpected command {other:#x}"
                ))),
            }
        })
    }
}

/// Install one rule and confirm the NIC holds what was asked for.
fn insert(iface: &str, rule: &SteerRule, vf_index: u32) -> Result<(), String> {
    let asked = flow_spec(rule, vf_index);
    let mut req = Rxnfc {
        cmd: ETHTOOL_SRXCLSRLINS,
        fs: asked,
        ..Rxnfc::default()
    };
    sys::ethtool(iface, &mut req)
        .map_err(|e| format!("inserting ntuple rule at loc {}: {e}", rule.location))?;

    // Read back, always. See the module docs: a wrong field offset
    // installs cleanly and matches the wrong traffic.
    let mut check = Rxnfc {
        cmd: ETHTOOL_GRXCLSRULE,
        fs: RxFlowSpec {
            location: rule.location,
            ..RxFlowSpec::default()
        },
        ..Rxnfc::default()
    };
    sys::ethtool(iface, &mut check)
        .map_err(|e| format!("reading back ntuple rule at loc {}: {e}", rule.location))?;
    if !matches(&asked, &check.fs) {
        return Err(format!(
            "ntuple rule at loc {} is not what was asked for — the NIC reports flow_type {:#x}, \
             cookie {:#x}; expected {:#x}, {:#x}. Refusing to steer traffic into a rule whose \
             match is unknown",
            rule.location,
            check.fs.flow_type,
            check.fs.ring_cookie,
            asked.flow_type,
            asked.ring_cookie
        ));
    }
    Ok(())
}

/// Remove one rule by location.
fn delete(iface: &str, location: u32) -> Result<(), String> {
    let mut req = Rxnfc {
        cmd: ETHTOOL_SRXCLSRLDEL,
        fs: RxFlowSpec {
            location,
            ..RxFlowSpec::default()
        },
        ..Rxnfc::default()
    };
    sys::ethtool(iface, &mut req)
        .map_err(|e| format!("deleting ntuple rule at loc {location}: {e}"))
}

/// The real [`crate::runtime::Steering`], replacing the placeholder.
pub struct NtupleSteering {
    /// `(PF iface, VF index)` for every port configured `steer on`.
    ///
    /// A list because steering is per-port — it is the canary lever, and
    /// the rollout turns it one port at a time — and because each PF
    /// steers into *its own* VF, so the ring_cookie differs per entry.
    ports: Vec<(String, u32)>,
    plan: RuleSet,
    /// `(iface, location)` currently installed. Per-iface because the
    /// same location number exists on every PF, and removing one from
    /// the wrong interface would leave traffic steered while reporting
    /// the rule gone. The state file's mirror of this is what lets a
    /// later `detach --all` remove rules this process did not install.
    installed: Vec<(String, u32)>,
}

impl NtupleSteering {
    pub fn new(ports: Vec<(String, u32)>, plan: RuleSet) -> Self {
        Self {
            ports,
            plan,
            installed: Vec::new(),
        }
    }

    /// Remove `victims`, **keeping whatever would not come out**.
    ///
    /// One routine because there are two callers — `steer`'s rollback and
    /// `unsteer` — and they must agree on the half that matters: a rule
    /// the NIC would not delete is still steering traffic, so it has to
    /// stay in `installed`. `Ok` from `unsteer` is what releases the VF,
    /// and a rollback that dropped its failures would empty the list, let
    /// a later `unsteer` find nothing, and hand back a VF with a live
    /// rule pointing into it.
    ///
    /// Returns the failures, formatted for the caller's message.
    fn remove_all(&mut self, victims: Vec<(String, u32)>) -> Vec<String> {
        let mut failed = Vec::new();
        for (iface, loc) in victims {
            if let Err(e) = delete(&iface, loc) {
                failed.push(format!("{iface} loc {loc}: {e}"));
                self.installed.push((iface, loc));
            }
        }
        failed
    }

    /// Adopt locations a previous process installed.
    ///
    /// Without this a restart cannot remove them: the plan would be
    /// rebuilt identically, but `unsteer` removes what *this* object
    /// installed, and a fresh object has installed nothing. The rules
    /// would outlive every process that knew about them and keep
    /// diverting traffic to a VF nobody owns.
    ///
    /// The record comes from
    /// [`crate::resources::ResourceState::steer_rules`], written by
    /// [`crate::runtime::IdentityStore::steering_changed`] after every
    /// change. Both halves shipped in #127 with nothing between them.
    pub fn adopt_installed(&mut self, installed: Vec<(String, u32)>) {
        self.installed = installed;
    }

    /// What the NIC should hold, from the current ports and plan.
    fn desired(&self) -> Vec<(String, u32)> {
        let mut out = Vec::with_capacity(self.ports.len() * self.plan.rules.len());
        for (iface, _) in &self.ports {
            for rule in &self.plan.rules {
                out.push((iface.clone(), rule.location));
            }
        }
        out
    }
}

impl crate::runtime::Steering for NtupleSteering {
    fn configured_ports(&self) -> usize {
        self.ports.len()
    }

    fn steer(&mut self) -> Result<(), String> {
        if self.plan.rules.is_empty() {
            return Err(
                "nothing to steer: the allowlist produced no rules for this NIC (see \
                 `packetframe feasibility`, capability `vpp.steering.budget`)"
                    .into(),
            );
        }
        // Clear anything the ledger holds that the current target does
        // not — rules from a previous allowlist, or from a port that has
        // since gone `steer off`. Without this, a reconfigure would
        // install the new set ALONGSIDE the old one and leave prefixes
        // diverted that the operator had just removed from the
        // allowlist, with nothing naming them.
        //
        // Before the inserts, not after: the two sets can overlap in
        // slot numbers, and removing afterwards would delete rules the
        // insert loop had just written.
        let desired = self.desired();
        let stale: Vec<(String, u32)> = self
            .installed
            .iter()
            .filter(|e| !desired.contains(e))
            .cloned()
            .collect();
        self.installed.retain(|e| !stale.contains(e));
        let failed = self.remove_all(stale);
        if !failed.is_empty() {
            // Refusing here rather than installing over them. A rule
            // that would not come out is still matching its old prefix,
            // and the new set may reuse its slot — so proceeding would
            // leave the NIC in a state neither the ledger nor the
            // operator could describe.
            return Err(format!(
                "{} stale ntuple rule(s) from the previous steering target could not be \
                 removed ({}); the new rules were NOT installed, because they may reuse \
                 those slots",
                failed.len(),
                failed.join(", ")
            ));
        }

        for (iface, vf_index) in &self.ports {
            for rule in &self.plan.rules {
                if let Err(e) = insert(iface, rule, *vf_index) {
                    // All-or-nothing. A partially steered port divides
                    // traffic between the tiers along a line nobody chose,
                    // so back out what landed before reporting the failure.
                    let victims = std::mem::take(&mut self.installed);
                    let rollback = self.remove_all(victims);
                    return Err(if rollback.is_empty() {
                        format!("{e}; every rule installed before it was removed")
                    } else {
                        // The rules that would not come out are still
                        // diverting traffic. Named individually because the
                        // operator has to remove them by hand before the VF
                        // can be released.
                        format!(
                            "{e}; AND the rollback did not complete ({}) — those rules are still \
                         steering traffic to the VF",
                            rollback.join(", ")
                        )
                    });
                }
                // A SET, not a log. The supervisor re-emits `Action::Steer`
                // for a VPP it already believes steered — the UniFi
                // controller wipes classifier state on provisioning, so
                // re-asserting is the reconcile step — and appending
                // unconditionally recorded every slot twice. `unsteer`
                // then deleted each twice, the second delete failed
                // because the rule was already gone, and a perfectly
                // clean teardown reported rules it could not remove and
                // withheld the VF.
                let entry = (iface.clone(), rule.location);
                if !self.installed.contains(&entry) {
                    self.installed.push(entry);
                }
            }
        }
        Ok(())
    }

    fn unsteer(&mut self) -> Result<(), String> {
        // Same routine the rollback uses, so the two cannot disagree
        // about what happens to a rule that would not come out.
        let victims = std::mem::take(&mut self.installed);
        let failed = self.remove_all(victims);
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} ntuple rule(s) could not be removed ({}); traffic is still being steered \
                 into the VF, so it must not be released",
                failed.len(),
                failed.join(", ")
            ))
        }
    }

    fn installed(&self) -> Vec<(String, u32)> {
        self.installed.clone()
    }

    fn retarget(&mut self, ports: Vec<(String, u32)>, plan: RuleSet) {
        self.ports = ports;
        self.plan = plan;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::steer::{McamBudget, RuleSet};
    use packetframe_common::fib::IpPrefix;
    use std::net::Ipv4Addr;

    fn rule(side: Side, loc: u32) -> SteerRule {
        SteerRule {
            prefix: Ipv4Addr::new(23, 191, 200, 0),
            prefix_len: 24,
            side,
            location: loc,
        }
    }

    /// The cookie, which nothing in the uapi documents and `ethtool`'s
    /// own keyword gets wrong on this driver.
    #[test]
    fn ring_cookie_offsets_the_vf_index_by_one() {
        assert_eq!(ring_cookie(0), 1u64 << 32);
        assert_eq!(ring_cookie(1), 2u64 << 32);
        // The PF's queue 0 is cookie 0, so a rule encoding VF 0 as 0
        // would steer to the PF and look like it worked.
        assert_ne!(ring_cookie(0), 0);
    }

    #[test]
    fn masks_cover_both_ends_without_shifting_by_32() {
        assert_eq!(mask_for(24), 0xffff_ff00);
        assert_eq!(mask_for(32), u32::MAX);
        assert_eq!(mask_for(0), 0);
    }

    /// Source and destination rules must populate DIFFERENT halves of
    /// the spec.
    ///
    /// `ethtool_usrip4_spec` puts ip4src first and ip4dst second, so a
    /// side that wrote the wrong offset would produce two rules matching
    /// the same field — one of them on traffic nobody meant to steer,
    /// and both looking installed.
    #[test]
    fn src_and_dst_populate_different_halves_of_the_spec() {
        let src = flow_spec(&rule(Side::Src, 10), 0);
        let dst = flow_spec(&rule(Side::Dst, 11), 0);

        assert_eq!(&src.h_u.hdata[0..4], &[23, 191, 200, 0], "ip4src");
        assert_eq!(
            &src.h_u.hdata[4..8],
            &[0, 0, 0, 0],
            "src rule leaves ip4dst unset"
        );
        assert_eq!(&dst.h_u.hdata[4..8], &[23, 191, 200, 0], "ip4dst");
        assert_eq!(
            &dst.h_u.hdata[0..4],
            &[0, 0, 0, 0],
            "dst rule leaves ip4src unset"
        );

        // The mask is the NETMASK — a set bit matches. These are the
        // literal bytes `GRXCLSRULE` returned from a rule this NIC
        // accepted, not a rendering of them: `ethtool -n` prints the
        // complement of what it stores, and believing its display is how
        // this file briefly shipped the inverse.
        assert_eq!(&src.m_u.hdata[0..4], &[255, 255, 255, 0], "ip4src /24");
        assert_eq!(&dst.m_u.hdata[4..8], &[255, 255, 255, 0], "ip4dst /24");

        // Every field this rule does not name stays ZERO, which is what
        // ignores it. All-ones there asks the NIC to match tos, proto,
        // ip_ver, l4_4_bytes and the sibling address against zero, and
        // the AF answers EOPNOTSUPP for the whole rule. Asserted across
        // the rest of the union rather than just the sibling address,
        // because the failure came from the fields nobody was looking at.
        assert_eq!(
            &src.m_u.hdata[4..],
            &[0u8; 48][..],
            "a src rule leaves ip4dst and every other mask at zero"
        );
        assert_eq!(
            &dst.m_u.hdata[0..4],
            &[0, 0, 0, 0],
            "a dst rule masks no src"
        );
        assert_eq!(
            &dst.m_u.hdata[8..],
            &[0u8; 44][..],
            "a dst rule masks no tos, proto or l4_4_bytes"
        );

        // `ip_ver`, carried because the accepted sample carries it.
        assert_eq!(src.h_u.hdata[IP_VER_OFFSET], ETH_RX_NFC_IP4);
        assert_eq!(src.m_u.hdata[IP_VER_OFFSET], 0, "and masked off");
    }

    /// The readback comparison must reject the differences that change
    /// behaviour and tolerate the ones that do not.
    #[test]
    fn the_readback_check_rejects_what_changes_forwarding() {
        let asked = flow_spec(&rule(Side::Src, 10), 0);
        assert!(matches(&asked, &asked), "identical must match");

        // A driver normalising a field we never set is not a mismatch.
        let mut normalised = asked;
        normalised.h_ext.vlan_tci = 0x1234;
        assert!(matches(&asked, &normalised), "untouched fields may differ");

        // These four each change where traffic goes.
        for mutate in [
            (|f: &mut RxFlowSpec| f.ring_cookie = ring_cookie(1)) as fn(&mut RxFlowSpec),
            |f: &mut RxFlowSpec| f.location = 99,
            |f: &mut RxFlowSpec| f.flow_type = 0x01,
            |f: &mut RxFlowSpec| f.h_u.hdata[0] = 24,
            |f: &mut RxFlowSpec| f.m_u.hdata[3] = 0xff,
        ] {
            let mut got = asked;
            mutate(&mut got);
            assert!(
                !matches(&asked, &got),
                "a difference that changes forwarding must be caught"
            );
        }
    }

    /// Slots come from the NIC's table, and occupied ones are not slots.
    ///
    /// The defect this replaces was a budget that named locations the
    /// driver would never accept, so the assertions are about the budget
    /// *tracking the table* rather than about any particular number: a
    /// test pinning 16 would pass just as well against a second
    /// hardcoded constant.
    #[test]
    fn the_budget_follows_the_nic_rather_than_a_constant() {
        use crate::runtime::Steering as _;
        sys::reset();

        let empty = McamBudget::for_ifaces(["eth0"]).expect("fake NIC answers");
        assert_eq!(
            empty.free.len(),
            FALLBACK_TABLE_SIZE as usize,
            "an untouched table offers every location"
        );
        assert_eq!(
            empty.free.first(),
            Some(&(FALLBACK_TABLE_SIZE - 1)),
            "highest first, to stay clear of whatever the vendor installs low"
        );

        // A smaller table yields a smaller budget, with no code change.
        sys::set_table_size(4);
        let small = McamBudget::for_ifaces(["eth0"]).expect("fake NIC answers");
        assert_eq!(small.free, vec![3, 2, 1, 0]);

        // And an allowlist that no longer fits is refused whole rather
        // than truncated into a half-steered port.
        let e = RuleSet::plan(
            &[
                IpPrefix::V4 {
                    addr: [10, 0, 0, 0],
                    prefix_len: 24,
                },
                IpPrefix::V4 {
                    addr: [10, 1, 0, 0],
                    prefix_len: 24,
                },
                IpPrefix::V4 {
                    addr: [10, 2, 0, 0],
                    prefix_len: 24,
                },
            ],
            small,
        )
        .expect_err("six rules cannot fit four slots");
        assert!(e.contains("only 4 slot(s) are free"), "{e}");

        // Rules already in the table are excluded, not overwritten —
        // including ones this module did not install.
        sys::set_table_size(FALLBACK_TABLE_SIZE);
        let mut s = NtupleSteering::new(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));
        s.steer().expect("installs at 15 and 14");
        let after = McamBudget::for_ifaces(["eth0"]).expect("fake NIC answers");
        assert!(
            !after.free.contains(&15) && !after.free.contains(&14),
            "occupied slots must not be offered again: {:?}",
            after.free
        );
        assert_eq!(after.free.first(), Some(&13), "the next free one is next");
    }

    /// A plan with no rules refuses rather than reporting success.
    ///
    /// `Ok` from `steer` becomes `Event::Steered`, which is what tells
    /// the supervisor traffic is diverted — so a no-op that returned
    /// `Ok` would put the module in `Steered` with nothing steered, and
    /// health would report the offload carrying traffic it never saw.
    #[test]
    fn steering_an_empty_plan_is_refused() {
        use crate::runtime::Steering as _;
        let mut s = NtupleSteering::new(vec![("eth0".into(), 0)], RuleSet::default());
        let e = s.steer().expect_err("must refuse");
        assert!(e.contains("nothing to steer"), "{e}");
        assert!(s.installed().is_empty());
    }

    /// A rule that would not delete STAYS recorded.
    ///
    /// This is the invariant `steer`'s rollback used to break while
    /// `unsteer`, thirty lines away, got it right: the rollback took the
    /// list, recorded delete failures in a message, and left `installed`
    /// empty. A later `unsteer` then found nothing, returned `Ok` — and
    /// `Ok` from unsteer is precisely what releases the VF — handing back
    /// a VF with a live rule still steering traffic into it.
    ///
    /// Both paths now share `remove_all`, so they cannot disagree.
    #[test]
    fn a_rule_that_will_not_delete_stays_recorded() {
        use crate::runtime::Steering as _;
        sys::reset();
        sys::wedge_delete(&[1024, 1025]);
        let mut s = NtupleSteering::new(vec![("eth0".into(), 0)], RuleSet::default());
        s.adopt_installed(vec![("eth0".into(), 1024), ("eth0".into(), 1025)]);

        let victims = std::mem::take(&mut s.installed);
        let failed = s.remove_all(victims);
        assert_eq!(failed.len(), 2, "both deletions failed on this host");
        assert_eq!(
            s.installed().len(),
            2,
            "a rule that would not come out must stay recorded, or the next \
             unsteer reports success over live steering"
        );

        // And that is what makes the refusal reachable: unsteer must not
        // report Ok while anything is still installed.
        let e = s.unsteer().expect_err("must refuse while rules remain");
        assert!(e.contains("must not be released"), "{e}");
        assert_eq!(s.installed().len(), 2, "still recorded after the refusal");
    }

    /// Adopted locations survive into `unsteer`.
    ///
    /// Without adoption a restarted process rebuilds the same plan but
    /// has installed nothing, so `unsteer` would remove nothing and
    /// report success — leaving rules that outlive every process that
    /// knew about them, still steering into a VF nobody owns.
    #[test]
    fn adopted_locations_are_what_unsteer_removes() {
        use crate::runtime::Steering as _;
        let allow = vec![IpPrefix::V4 {
            addr: [23, 191, 200, 0],
            prefix_len: 24,
        }];
        let plan = RuleSet::plan(&allow, McamBudget::default()).expect("fits");
        let mut s = NtupleSteering::new(vec![("eth0".into(), 0)], plan);
        assert!(
            s.installed().is_empty(),
            "a fresh object has installed nothing"
        );

        s.adopt_installed(vec![("eth0".into(), 1024), ("eth0".into(), 1025)]);
        assert_eq!(
            s.installed(),
            vec![("eth0".to_string(), 1024), ("eth0".to_string(), 1025)],
            "the previous process's rules are now this one's to remove"
        );
    }

    fn plan_for(prefixes: &[[u8; 4]]) -> RuleSet {
        let allow: Vec<IpPrefix> = prefixes
            .iter()
            .map(|a| IpPrefix::V4 {
                addr: *a,
                prefix_len: 24,
            })
            .collect();
        RuleSet::plan(&allow, McamBudget::default()).expect("fits")
    }

    /// The happy path, which had never executed anywhere.
    ///
    /// Asserts the ledger against the NIC rather than against itself:
    /// `installed()` is the list teardown acts on, and the only thing
    /// that makes it meaningful is that it names exactly the rules the
    /// hardware holds.
    #[test]
    fn a_steer_installs_the_plan_and_an_unsteer_removes_all_of_it() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = NtupleSteering::new(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));

        s.steer().expect("installs");
        assert_eq!(
            sys::rules(),
            vec![("eth0".to_string(), 14), ("eth0".to_string(), 15)],
            "both directions, in the planned slots"
        );
        // Sorted on both sides: the ledger is a SET (that is #127's
        // fix), so it holds no order worth asserting, and slots are now
        // taken highest-first — comparing raw would test the direction
        // the budget hands out locations rather than the property that
        // matters, which is that the two name the same rules.
        let mut ledger = s.installed();
        ledger.sort();
        assert_eq!(ledger, sys::rules(), "the ledger names what the NIC holds");

        s.unsteer().expect("removes");
        assert!(sys::rules().is_empty(), "nothing left in the NIC");
        assert!(s.installed().is_empty(), "and nothing left in the ledger");
    }

    /// Re-asserting steering must not record the same slot twice.
    ///
    /// The supervisor deliberately re-emits `Action::Steer` for a VPP it
    /// already believes steered, because the UniFi controller wipes
    /// classifier state on provisioning. With the ledger appending, the
    /// second pass recorded every slot a second time; `unsteer` then
    /// deleted each twice, the second delete returned ENOENT, and a
    /// teardown that had in fact removed every rule reported failures
    /// and **withheld the VF**.
    ///
    /// So the assertion is on the ledger's cardinality, not on the
    /// removal succeeding — the removal succeeding is the symptom, the
    /// set property is the invariant.
    #[test]
    fn re_asserting_steering_records_each_slot_once() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = NtupleSteering::new(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));

        s.steer().expect("first");
        s.steer()
            .expect("re-assert, as the supervisor does on every Ready");
        assert_eq!(
            s.installed().len(),
            2,
            "two rules exist, so two must be recorded — however many times they were asserted"
        );
        s.unsteer()
            .expect("a clean teardown must stay clean across a re-assert");
    }

    /// A retarget removes what the old target had and installs the new,
    /// leaving nothing behind.
    ///
    /// This is the reconfigure path: an operator drops a prefix from the
    /// allowlist and SIGHUPs. Without the stale-removal the old rules
    /// stay in the NIC — traffic for a prefix the operator explicitly
    /// removed keeps being diverted, and nothing anywhere names it,
    /// because the ledger only ever describes the current plan.
    #[test]
    fn a_retarget_leaves_only_the_new_rules() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = NtupleSteering::new(
            vec![("eth0".into(), 0)],
            plan_for(&[[10, 0, 0, 0], [10, 1, 0, 0]]),
        );
        s.steer().expect("installs four");
        assert_eq!(sys::rules().len(), 4);

        // Down to one prefix: slots 13/12 are no longer wanted.
        s.retarget(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));
        s.steer().expect("reconciles");

        assert_eq!(
            sys::rules(),
            vec![("eth0".to_string(), 14), ("eth0".to_string(), 15)],
            "the withdrawn prefix's rules are gone from the NIC, not merely unrecorded"
        );
        let mut ledger = s.installed();
        ledger.sort();
        assert_eq!(ledger, sys::rules());
    }

    /// A retarget that cannot clear a stale rule installs NOTHING.
    ///
    /// The new plan may reuse the slot the old rule is sitting in, so
    /// proceeding would leave the NIC holding a mix of two targets that
    /// neither the ledger nor the operator could describe. And the
    /// undeletable rule stays recorded — it is still steering traffic,
    /// and it is what a later `detach --all` has to find.
    #[test]
    fn a_retarget_that_cannot_clear_the_old_rules_installs_nothing() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = NtupleSteering::new(
            vec![("eth0".into(), 0)],
            plan_for(&[[10, 0, 0, 0], [10, 1, 0, 0]]),
        );
        s.steer().expect("installs four");

        sys::wedge_delete(&[13]);
        s.retarget(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));
        let e = s.steer().expect_err("must refuse");

        assert!(
            e.contains("could not be removed") && e.contains("NOT installed"),
            "the operator has to learn both halves: what stayed, and that nothing new landed: {e}"
        );
        assert!(
            s.installed().contains(&("eth0".to_string(), 13)),
            "the rule that would not come out must stay in the ledger, or detach cannot find it"
        );
    }

    /// A failed insert backs out everything, including rules that were
    /// already installed before this attempt.
    ///
    /// All-or-nothing is the point: a port holding half its rules
    /// forwards some allowlisted traffic through VPP and the rest
    /// through the kernel. Slot 12 — the last of four — is made to
    /// refuse, so three rules are already in the NIC when the failure
    /// lands.
    #[test]
    fn a_failed_insert_leaves_the_port_unsteered() {
        use crate::runtime::Steering as _;
        sys::reset();
        sys::wedge_insert(&[12]);
        let mut s = NtupleSteering::new(
            vec![("eth0".into(), 0)],
            plan_for(&[[10, 0, 0, 0], [10, 1, 0, 0]]),
        );

        let e = s.steer().expect_err("the last rule cannot be installed");
        assert!(
            e.contains("every rule installed before it was removed"),
            "{e}"
        );
        assert!(
            sys::rules().is_empty(),
            "the three that landed must not survive the failure — a half-steered port is \
             a forwarding policy nobody chose"
        );
        assert!(s.installed().is_empty());
    }
}
