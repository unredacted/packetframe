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
//!
//! ## Removal reads first, too
//!
//! `ETHTOOL_SRXCLSRLDEL` names a **location**, not a rule, and the
//! ledger's claim on a location can go stale in exactly the way the
//! audit already documents: an insert at an occupied slot replaces
//! rather than fails, so a slot this module recorded can hold somebody
//! else's classifier rule. Deleting by location alone therefore let a
//! reconfigure or a teardown break traffic belonging to a rule nobody
//! here installed (review finding).
//!
//! So [`NtupleSteering::remove_all`] reads each location back before
//! it deletes — and the test it applies is deliberately **not** the
//! audit's. See its doc comment: the audit asks "is this our rule", the
//! removal asks "will this keep steering into the VF we are about to
//! release", and the second question has to be answered `yes` for
//! rules the first would disown.

use crate::runtime::SteerOutcome;
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

/// `ETHTOOL_RX_FLOW_SPEC_RING_VF`, the VF field of a `ring_cookie`.
const RING_VF_MASK: u64 = 0x0000_00FF_0000_0000;
/// `ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF`.
const RING_VF_SHIFT: u32 = 32;

/// The VF a `ring_cookie` names — `ethtool_get_flow_spec_ring_vf()`.
///
/// The cookie is two fields, not one number: the VF in bits 32..40 and a
/// **queue index within that VF** in bits 0..32
/// (`ETHTOOL_RX_FLOW_SPEC_RING`). Everything this module installs leaves
/// the queue at zero, so [`ring_cookie`] and the whole cookie agree for
/// our own rules and comparing the raw `u64` looks right.
///
/// It is not right for the question [`NtupleSteering::remove_all`] asks.
/// A rule steering to *queue 3 of our VF* carries `(vf + 1) << 32 | 3`,
/// which is not equal to anything we would write — so whole-cookie
/// equality classified it as somebody else's, left it in place, and let
/// `unsteer` report the VF safe to release with MCAM still pointing
/// into it (review finding on this PR). That is the blackhole the
/// readback was added to prevent, reintroduced by the comparison meant
/// to prevent it.
///
/// Returns the field, so `0` means the PF: VF indices are offset by one
/// in the cookie, which is what [`ring_cookie`]'s `+ 1` is.
fn ring_cookie_vf(cookie: u64) -> u64 {
    (cookie & RING_VF_MASK) >> RING_VF_SHIFT
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

/// Whether a rule read back from the NIC is still ours in the sense the
/// AUDIT cares about: same match, and no narrower.
///
/// [`matches`] deliberately compares only the bytes we set, because a
/// driver may normalise fields we left zero and refusing a correctly
/// installed rule would be worse than tolerating a cosmetic difference.
/// That tolerance has a hole the audit cannot afford: a foreign rule
/// that keeps our addresses and ring cookie while ADDING a protocol,
/// TOS or L4 constraint compares equal, and quietly stops offloading
/// some of the traffic we think is steered (review finding).
///
/// So this adds the whole MASK. The mask is what decides breadth — a
/// value with no mask bits behind it constrains nothing, which is
/// exactly why `matches` can ignore values — so comparing every mask
/// byte catches a narrowing without inheriting the false-refusal risk.
///
/// Safe to be this strict because the NIC was asked. Reading our own
/// four rules back on the shadow (2026-08-11) returned stored masks of
/// zero for TOS, protocol and L4 bytes, on rules installed with those
/// left zero — the driver invents nothing there. Note `ethtool -n`
/// PRINTS masks complemented, so those read as `0xff`/`0xffffffff` on
/// screen; the stored bytes are zero. Mistaking the display for the
/// wire cost a merged PR once already (#134).
///
/// Separate from `matches` on purpose, and used only by the audit: a
/// false positive here costs a Degraded health line, while the same
/// false positive in `insert` refuses to steer traffic. Those are not
/// worth the same and must not share a predicate.
fn audit_matches(asked: &RxFlowSpec, got: &RxFlowSpec) -> bool {
    matches(asked, got) && asked.m_u.hdata == got.m_u.hdata
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
        unreadable: Vec<u32>,
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
                unreadable: Vec::new(),
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

    /// Make GRXCLSRULE fail at these locations with something that is
    /// NOT ENOENT — an EIO-shaped fault, which says nothing about
    /// whether a rule is there.
    pub(crate) fn wedge_read(locations: &[u32]) {
        NIC.with(|n| n.borrow_mut().unreadable = locations.to_vec());
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

    /// Copy the rule at `from` over the one at `to`, keeping `to`'s
    /// location. Both slots then hold the SAME match — which is what an
    /// out-of-band writer does when it reuses our slot for a rule we
    /// also happen to want elsewhere, and it leaves whatever `from`
    /// used to match unoffloaded.
    pub(crate) fn duplicate_behind_back(iface: &str, from: u32, to: u32) {
        NIC.with(|n| {
            let mut nic = n.borrow_mut();
            if let Some(src) = nic.rules.get(&(iface.to_string(), from)).copied() {
                let mut copy = src;
                copy.location = to;
                nic.rules.insert((iface.to_string(), to), copy);
            }
        });
    }

    /// Narrow the rule at `loc` — same addresses, same ring cookie, but
    /// an added protocol constraint. What an out-of-band writer does
    /// when it reuses our slot for something more specific: the slot
    /// stays occupied and the addresses still match, so anything
    /// comparing only those reports it as ours.
    pub(crate) fn narrow_behind_back(iface: &str, loc: u32) {
        NIC.with(|n| {
            let mut nic = n.borrow_mut();
            if let Some(fs) = nic.rules.get_mut(&(iface.to_string(), loc)) {
                // `proto` lives at offset 14 of `ethtool_usrip4_spec`;
                // a mask byte there is what makes the rule narrower.
                fs.m_u.hdata[14] = 0xff;
                fs.h_u.hdata[14] = 6; // TCP only
            }
        });
    }

    /// Overwrite a location with a DIFFERENT rule, the way an insert
    /// from outside this process does — inserts at an occupied location
    /// replace rather than fail, so the slot stays listed while our
    /// rule is gone.
    ///
    /// The cookie is a target that is not ours, which is what makes this
    /// a stranger's rule to the removal path as well as to the audit.
    pub(crate) fn replace_behind_back(iface: &str, loc: u32) {
        replace_behind_back_targeting(iface, loc, 0xDEAD_BEEF);
    }

    /// The same overwrite, with the ring cookie chosen by the caller.
    ///
    /// Separate from the audit's concerns entirely: removal keys on the
    /// cookie, so a foreign rule that happens to steer into the VF this
    /// module owns is a different case from one that does not, and only
    /// this can build it.
    pub(crate) fn replace_behind_back_targeting(iface: &str, loc: u32, cookie: u64) {
        NIC.with(|n| {
            let mut nic = n.borrow_mut();
            let foreign = super::RxFlowSpec {
                location: loc,
                ring_cookie: cookie,
                ..super::RxFlowSpec::default()
            };
            nic.rules.insert((iface.to_string(), loc), foreign);
        });
    }

    /// Drop a rule WITHOUT going through `delete` — what a UniFi
    /// provisioning push, a firmware event, or an operator with
    /// `ethtool -N <if> delete <loc>` does. Nothing tells the module.
    pub(crate) fn remove_behind_back(iface: &str, loc: u32) {
        NIC.with(|n| {
            n.borrow_mut().rules.remove(&(iface.to_string(), loc));
        });
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
                ETHTOOL_GRXCLSRULE if nic.unreadable.contains(&req.fs.location) => {
                    Err(std::io::Error::other("EIO: readback failed"))
                }
                ETHTOOL_GRXCLSRULE => match nic.rules.get(&key) {
                    Some(stored) => {
                        req.fs = *stored;
                        Ok(())
                    }
                    // `NotFound`, not a bare string: ENOENT is how the
                    // real driver answers for an empty location, and
                    // `delete` classifies on the error KIND — a fake
                    // whose absent-rule error is unclassifiable would
                    // hide exactly the branch the fake exists to test.
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "ENOENT: no rule at that location",
                    )),
                },
                ETHTOOL_SRXCLSRLDEL => {
                    if nic.undeletable.contains(&req.fs.location) {
                        return Err(std::io::Error::other("EBUSY: rule is pinned"));
                    }
                    match nic.rules.remove(&key) {
                        Some(_) => Ok(()),
                        None => Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "ENOENT: no rule at that location",
                        )),
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

/// Read back whatever the NIC holds at `location`.
///
/// `Ok(None)` is ENOENT — the driver's answer for a location holding
/// nothing. Every other error is returned: a read that failed says
/// nothing about what is there, and the callers must not read it as
/// "empty".
fn read_rule(iface: &str, location: u32) -> Result<Option<RxFlowSpec>, String> {
    let mut req = Rxnfc {
        cmd: ETHTOOL_GRXCLSRULE,
        fs: RxFlowSpec {
            location,
            ..RxFlowSpec::default()
        },
        ..Rxnfc::default()
    };
    match sys::ethtool(iface, &mut req) {
        Ok(()) => Ok(Some(req.fs)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("reading ntuple rule at loc {location}: {e}")),
    }
}

/// What a ledger location holds, as far as **removal** is concerned.
///
/// Not the same question the audit asks, and the difference is the
/// point — see [`NtupleSteering::remove_all`].
enum Occupant {
    /// Nothing. The removal's postcondition already holds; see
    /// [`Removal::AlreadyAbsent`], which is the same fact arriving one
    /// ioctl later.
    Absent,
    /// A rule whose `ring_cookie` names the VF this module owns on this
    /// interface. Ours, or one we cannot recognise that points into our
    /// VF anyway — and both must come out before the VF is released.
    IntoOurVf,
    /// A rule steering somewhere else, on an interface whose VF we know.
    /// Positive evidence the slot is not ours: our own rule is already
    /// gone, and this one is a stranger's to keep.
    Elsewhere(u64),
    /// Occupied, and nothing here can say by whom — no VF is known for
    /// this interface, so there is no cookie to compare against.
    Unattributable,
}

/// What removing one rule actually did.
enum Removal {
    Removed,
    /// The NIC answered ENOENT: no rule at that location. Absent IS
    /// the removal's postcondition — nothing there is steering traffic
    /// — so it counts as removed, not as a failure. The case is real,
    /// not defensive: the UniFi controller wipes classifier state on
    /// provisioning, so rules the ledger faithfully records can vanish
    /// while the daemon is down. Treating that as a failed delete kept
    /// the ledger populated forever — unsteer refused, the VF was
    /// withheld, and the deferred adopted reconciliation waited on an
    /// unsteer that could never be acknowledged (review finding).
    ///
    /// [`NtupleSteering::remove_all`] now reads the location first, so
    /// the wipe usually arrives as [`Occupant::Absent`] instead and this
    /// is what is left: the rule went away between the two ioctls. Kept
    /// because `delete` is the only thing that can observe that, and
    /// because the verdict is the same on both routes.
    ///
    /// ENOENT only. EBUSY, EINVAL and the rest keep failing loudly:
    /// they say nothing about whether a rule is still matching.
    AlreadyAbsent,
}

/// Remove one rule by location.
fn delete(iface: &str, location: u32) -> Result<Removal, String> {
    let mut req = Rxnfc {
        cmd: ETHTOOL_SRXCLSRLDEL,
        fs: RxFlowSpec {
            location,
            ..RxFlowSpec::default()
        },
        ..Rxnfc::default()
    };
    match sys::ethtool(iface, &mut req) {
        Ok(()) => Ok(Removal::Removed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removal::AlreadyAbsent),
        Err(e) => Err(format!("deleting ntuple rule at loc {location}: {e}")),
    }
}

/// The real [`crate::runtime::Steering`], replacing the placeholder.
pub struct NtupleSteering {
    /// `(PF iface, VF index)` for every PF this module holds a VF on —
    /// **whatever the steering target says**.
    ///
    /// An acquisition fact, not a steering one, and that is the whole
    /// reason it is separate from `ports`. Removal needs to know which
    /// VF a location's occupant would have to name to be ours, and it
    /// needs that most on the port the target has *stopped* steering:
    /// `bring_up` builds `ports` from the `steer on` ports only, so
    /// after a restart that turned a port off, `ports` cannot say, and
    /// `installed_as` — set only by a successful steer in this process —
    /// is `None`. Removal fell through to deleting by location there,
    /// which is the blind delete this module just stopped doing,
    /// surviving in exactly the case the ledger's claim is oldest and
    /// the rollback path cares most about (review finding on this PR).
    ///
    /// Fixed at attach. `reconfigure` accepts only the `steer` flag, so
    /// the set of PFs and their VFs cannot move under a running module,
    /// and `retarget` must not touch this.
    members: Vec<(String, u32)>,
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
    /// The target the LEDGER was last installed under.
    ///
    /// Kept for one purpose: a port the config just turned off leaves
    /// `ports`, and its ledger entries then have no expectation to be
    /// checked against — so "is this slot still ours" degenerated into
    /// "is this slot occupied", which is the ownership guess this audit
    /// has already been burned by twice. With the installed target in
    /// hand those rules get the same field-by-field comparison as
    /// everything else.
    ///
    /// Written by a SUCCESSFUL `steer` and by nothing else. The first
    /// version recorded the outgoing target on every `retarget`, which
    /// is the last thing *intended* rather than the last thing
    /// installed — so two reconfigures whose reconcile was refused (the
    /// completeness gate permits a second request from `Ready`) left it
    /// describing a target that had never reached the NIC. The rules
    /// actually there then matched nothing, were disowned as foreign,
    /// and vanished from the audit entirely: not missing, not surplus,
    /// not mentioned (review finding).
    ///
    /// `None` after a restart: the state file records locations, not
    /// what they were installed to hold, so ownership falls back to
    /// occupancy — see the non-member arm of `missing_from_nic`.
    installed_as: Option<(Vec<(String, u32)>, RuleSet)>,
}

impl NtupleSteering {
    /// `members` is every PF this module holds a VF on; `ports` is the
    /// subset the target steers. A constructor parameter rather than a
    /// setter because the two production callers are the only things
    /// that know the acquisition, and a `steering.set_members(..)` one
    /// of them forgets is precisely how `adopt_installed` shipped with
    /// no caller at all (#127).
    pub fn new(members: Vec<(String, u32)>, ports: Vec<(String, u32)>, plan: RuleSet) -> Self {
        Self {
            members,
            ports,
            plan,
            installed: Vec::new(),
            installed_as: None,
        }
    }

    /// The VF this module owns on `iface`, if anything knows.
    ///
    /// `members` answers for every acquired port including the ones the
    /// target does not steer, so it is asked first and is normally the
    /// only leg that fires. The other two are kept for callers holding
    /// less than the full acquisition: the steering target, then the
    /// last successful install. `None` only where nothing knows the
    /// interface at all.
    fn vf_for(&self, iface: &str) -> Option<u32> {
        let found = self
            .members
            .iter()
            .chain(self.ports.iter())
            .find(|(i, _)| i == iface);
        if let Some((_, vf)) = found {
            return Some(*vf);
        }
        let (ports, _) = self.installed_as.as_ref()?;
        ports.iter().find(|(i, _)| i == iface).map(|(_, v)| *v)
    }

    /// Read a ledger location and decide what removal owes it.
    ///
    /// The VF **field** of the cookie, not the whole cookie: its low 32
    /// bits are a queue index within the VF, so a rule aimed at another
    /// queue of our own VF still has to come out. See [`ring_cookie_vf`].
    fn occupant(&self, iface: &str, loc: u32) -> Result<Occupant, String> {
        let Some(got) = read_rule(iface, loc)? else {
            return Ok(Occupant::Absent);
        };
        match self.vf_for(iface) {
            Some(vf) if ring_cookie_vf(got.ring_cookie) == ring_cookie_vf(ring_cookie(vf)) => {
                Ok(Occupant::IntoOurVf)
            }
            Some(_) => Ok(Occupant::Elsewhere(got.ring_cookie)),
            None => Ok(Occupant::Unattributable),
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
    /// ## Which rules this is entitled to delete
    ///
    /// The delete ioctl names a location, and a location the ledger
    /// names may hold somebody else's rule — an insert at an occupied
    /// slot replaces rather than fails, which is the same fact
    /// `missing_from_nic` is careful about. Deleting blind therefore
    /// broke unrelated traffic on a reconfigure or a teardown, and
    /// unlike a wrong health line that is not recoverable by reading
    /// (review finding).
    ///
    /// So each location is read back first, and the test is the **VF
    /// field of the `ring_cookie`** ([`ring_cookie_vf`]), not the whole
    /// flow spec and not the whole cookie:
    ///
    /// - it names our VF → delete. Ours, or a rule we cannot recognise
    ///   that steers into our VF regardless — and `Ok` from `unsteer`
    ///   is what releases that VF, so leaving it is the blackhole this
    ///   routine's contract exists to prevent.
    /// - it names something else → leave it, and drop the entry. Our
    ///   rule at that slot is already gone, which is the removal's
    ///   postcondition; the occupant is a stranger's and its traffic is
    ///   not ours to break.
    /// - nothing there → already removed, as before.
    /// - the read failed for any other reason → a failure, so the entry
    ///   stays recorded and `unsteer` refuses. Unverifiable is not
    ///   unconstrained; on a NIC that will not answer, both the "do not
    ///   delete a stranger's rule" and the "do not release a steered VF"
    ///   halves point the same way, at the operator.
    ///
    /// The cookie rather than [`audit_matches`] because the two answer
    /// different questions. The audit asks *is this our rule*, and a
    /// false positive there costs a Degraded line. This asks *will this
    /// still be steering into the VF we are about to hand back*, and a
    /// false negative here blackholes traffic — so it must delete
    /// rules the audit would disown, and refuse only where the cookie
    /// proves the rule points elsewhere.
    ///
    /// ## The window this does not close
    ///
    /// The readback and the delete are two ioctls and nothing holds the
    /// table between them, so a writer that replaces a slot in that gap
    /// gets its rule deleted on the strength of a check that passed
    /// against the previous occupant (review finding). There is no fix
    /// available here, and it is worth writing down why rather than
    /// leaving the readback looking like a guarantee:
    /// `ETHTOOL_SRXCLSRLDEL` names a location and carries no expected
    /// value, so the uapi has no compare-and-delete; `rtnl_lock` makes
    /// each ioctl atomic but cannot be held across a pair from
    /// userspace; and the other writers — a UniFi provisioning push, a
    /// firmware event, an operator's `ethtool -N` — share no lock with
    /// this process at all.
    ///
    /// What it does is shrink that window from *every removal this
    /// module ever issued* to the microseconds between two syscalls.
    ///
    /// The symmetric worry — a rule aimed at our VF appearing at a
    /// disowned slot just before `unsteer` returns — is not a
    /// synchronisation problem in here at all. The same writer can
    /// install the same rule immediately AFTER the last delete, when the
    /// ledger is empty and the answer has already been given; that
    /// window is unbounded and no amount of checking inside this routine
    /// shortens it. What covers it is the teardown ORDERING — steering
    /// down, VPP killed, VF unbound last — and `detach --all` being
    /// re-runnable against whatever the NIC holds next.
    ///
    /// Where no VF is known for the interface — nothing in `members`,
    /// the target, or the last install names it — nothing can be proven
    /// and the location is deleted as this module always has. The
    /// tradeoff is documented in `docs/runbooks/vpp-offload.md`. Neither
    /// production caller lands there: both pass every acquired port, so
    /// a location's occupant is attributable even on a port the target
    /// has stopped steering, which is the case that most needs it.
    ///
    /// Returns the failures, formatted for the caller's message.
    fn remove_all(&mut self, victims: Vec<(String, u32)>) -> Vec<String> {
        let mut failed = Vec::new();
        for (iface, loc) in victims {
            match self.occupant(&iface, loc) {
                Ok(Occupant::IntoOurVf) => {}
                Ok(Occupant::Absent) => {
                    tracing::info!(
                        iface,
                        loc,
                        "ntuple rule was already gone — the controller wipes classifier \
                         state on provisioning — and absent is what a removal is for, so \
                         it counts as removed"
                    );
                    continue;
                }
                Ok(Occupant::Elsewhere(cookie)) => {
                    // Dropped from the ledger, not merely skipped: it is
                    // not ours, so it must not go back into the state
                    // file for a later `detach --all` to find and delete.
                    tracing::warn!(
                        iface,
                        loc,
                        cookie = format!("{cookie:#x}"),
                        "a location this ledger names holds a rule steering somewhere \
                         other than our VF; ours is already gone, so it is left alone \
                         rather than deleted — removing it would break traffic this \
                         module never claimed"
                    );
                    continue;
                }
                Ok(Occupant::Unattributable) => tracing::debug!(
                    iface,
                    loc,
                    "no VF is known for this interface, so the occupant cannot be \
                     attributed; removing by location, as the ledger recorded it"
                ),
                Err(e) => {
                    // The NIC would not say what is there. Deleting on
                    // that basis is the blind delete this readback
                    // exists to end, and reporting success would release
                    // a VF that may still be steered into.
                    failed.push(format!("{iface} loc {loc}: {e}"));
                    self.installed.push((iface, loc));
                    continue;
                }
            }
            match delete(&iface, loc) {
                Ok(Removal::Removed) => {}
                // The readback said something was there, so this is the
                // race rather than the provisioning wipe — but absent is
                // absent either way.
                Ok(Removal::AlreadyAbsent) => tracing::info!(
                    iface,
                    loc,
                    "ntuple rule went away between the readback and the delete; \
                     absent is what a removal is for, so it counts as removed"
                ),
                Err(e) => {
                    failed.push(format!("{iface} loc {loc}: {e}"));
                    self.installed.push((iface, loc));
                }
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
    ///
    /// **Deduplicated on the way in.** The ledger is a set — a location
    /// exists once on a NIC — and `steer` maintains that, but this
    /// arrives from a JSON file on disk, which is a boundary: an older
    /// build's unconditional append, or an edited file, can name a rule
    /// twice. The audit matches one planned rule to one location, so the
    /// second copy would find nothing left to match and report drift on
    /// a NIC that is perfectly correct — Degraded forever, and
    /// `reconfigure` would not clear it, since a duplicate is not stale
    /// (it IS in the desired set) and the insert loop's set-check only
    /// declines to add a THIRD copy. A false alarm with no remedy is
    /// worse than no alarm: it is what teaches an operator to stop
    /// reading the line.
    ///
    /// Fixed here rather than in the audit, deliberately. One planned
    /// rule accounting for one location is the property that catches a
    /// duplicated rule on the NIC itself; relaxing it to tolerate a
    /// malformed ledger would trade a real check for a cosmetic one.
    pub fn adopt_installed(&mut self, installed: Vec<(String, u32)>) {
        let found = installed.len();
        let mut seen = std::collections::HashSet::new();
        self.installed = installed
            .into_iter()
            .filter(|e| seen.insert(e.clone()))
            .collect();
        if self.installed.len() < found {
            tracing::info!(
                dropped = found - self.installed.len(),
                kept = self.installed.len(),
                "the state file named the same steering rule more than once; a \
                 location exists once on the NIC, so the ledger keeps it once"
            );
        }
    }

    /// Can the outgoing target prove this slot is **not** ours?
    ///
    /// `true` only when the last install covered this interface AND
    /// nothing it asked for matches what the NIC returned — that is
    /// positive evidence the rule at this location belongs to somebody
    /// else, so our own is already gone. `false` covers both "it is
    /// ours" and "there is nothing to check against", which is why the
    /// caller's message claims occupancy rather than ownership.
    ///
    /// One-to-one, like the member path: two locations holding a copy
    /// of the same installed rule cannot both be accounted for by it.
    fn install_disowns(
        &self,
        iface: &str,
        loc: u32,
        got: &RxFlowSpec,
        consumed: &mut std::collections::HashMap<String, Vec<bool>>,
    ) -> bool {
        let Some((ports, plan)) = &self.installed_as else {
            return false;
        };
        let Some(vf) = ports.iter().find(|(i, _)| i == iface).map(|(_, v)| *v) else {
            return false;
        };
        let taken = consumed
            .entry(iface.to_string())
            .or_insert_with(|| vec![false; plan.rules.len()]);
        let found = plan.rules.iter().enumerate().position(|(i, r)| {
            !taken[i]
                && audit_matches(
                    &RxFlowSpec {
                        location: loc,
                        ..flow_spec(r, vf)
                    },
                    got,
                )
        });
        match found {
            Some(i) => {
                taken[i] = true;
                false
            }
            None => true,
        }
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

    fn steer(&mut self) -> Result<SteerOutcome, String> {
        // Two ways to have nothing to install, and they are opposite
        // events.
        //
        // No PORT is the operator's answer: every port is `steer off`,
        // so the reconcile below removes whatever the previous target
        // left and reports `NothingToSteer` — the NIC holds nothing and
        // nothing is wanted. Refusing instead is what made the rollback
        // unrecoverable: an `unsteer` the NIC declines leaves rules in
        // `installed` and `steered` true, every later convergence
        // re-emits `Action::Steer`, and a refusal here returns before
        // the stale-rule removal that is the only thing that could
        // clear them.
        //
        // Ports but no RULES is a fault, and still refuses. Somebody
        // asked for a port to divert traffic and the allowlist or the
        // MCAM budget produced nothing to divert it with; reporting
        // that as a clean "nothing steered" would retire the want and
        // hide a broken allowlist behind the same line a deliberate
        // `steer off` prints.
        if !self.ports.is_empty() && self.plan.rules.is_empty() {
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
        // Here and nowhere else: the ledger now holds this target,
        // confirmed rule by rule by the readback inside `insert`. An
        // intent that never reached the NIC must not overwrite this —
        // that is what made a second refused reconfigure disown rules
        // that were really there.
        self.installed_as = Some((self.ports.clone(), self.plan.clone()));
        // From the LEDGER, not from `ports.is_empty()`. The ledger is
        // the postcondition the caller acts on — it is what
        // `steering_in_place` reads and what the state file records —
        // and every path that could leave it holding a rule under an
        // empty target has already returned `Err` above. Saying
        // "nothing is steered" while a location this object installed
        // is still in the NIC is the one lie the release rules cannot
        // survive.
        Ok(if self.installed.is_empty() {
            SteerOutcome::NothingToSteer
        } else {
            SteerOutcome::Steered
        })
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

    fn missing_from_nic(&self) -> Result<crate::runtime::SteeringAudit, String> {
        let mut missing = Vec::new();
        let mut read_errors: Vec<String> = Vec::new();
        // Which planned rule each interface has already accounted for.
        // ONE-TO-ONE: a planned rule satisfies at most one location.
        // Matching each location against "any planned rule"
        // independently let a writer replace our source-prefix rule
        // with a second copy of the destination-prefix one — both
        // locations then matched something planned, both passed, and
        // source traffic had quietly lost its offload (review finding).
        let mut consumed: std::collections::HashMap<&str, Vec<bool>> =
            std::collections::HashMap::new();
        // Per-interface tallies for the second direction below: how many
        // of this interface's locations already reported drift, and how
        // many could not be read at all. Both consume nothing from the
        // plan, so both would otherwise read as "a planned rule with no
        // rule on the NIC" and be counted a second time.
        // Ledger locations that hold nothing, and ones that hold
        // something this target did not ask for. Neither is a complaint
        // by itself: both are candidate ANSWERS to "where did the rule
        // this target wants go", and what is left over once every
        // homeless rule has an answer is surplus.
        let mut empty: std::collections::HashMap<&str, Vec<u32>> = std::collections::HashMap::new();
        let mut occupied: std::collections::HashMap<&str, Vec<(u32, RxFlowSpec)>> =
            std::collections::HashMap::new();
        let mut unreadable: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();

        // Rules on a port the target no longer steers. Skipping them
        // entirely was the bug: `retarget` drops a port the config just
        // set `steer off`, and the reconcile that would clear its rules
        // can refuse at the completeness gate and never run — so the
        // ledger goes on naming rules that divert traffic on a port an
        // operator asked to be quiet, and the audit looked straight past
        // them (review finding). That is the rollback path, where the
        // whole point is getting traffic OFF a port.
        let mut stray = Vec::new();
        // One-to-one accounting for the outgoing target, same rule as
        // `consumed` above and for the same reason.
        let mut installed_consumed: std::collections::HashMap<String, Vec<bool>> =
            std::collections::HashMap::new();

        for (iface, loc) in &self.installed {
            // `None` = the current target does not steer this port.
            let member = self.ports.iter().find(|(i, _)| i == iface).map(|(_, v)| *v);
            let mut check = Rxnfc {
                cmd: ETHTOOL_GRXCLSRULE,
                fs: RxFlowSpec {
                    location: *loc,
                    ..RxFlowSpec::default()
                },
                ..Rxnfc::default()
            };
            match sys::ethtool(iface, &mut check) {
                // Occupied on a port the target does not steer.
                //
                // Occupancy alone is NOT ownership — the same mistake
                // this audit made on the member path, where an insert
                // at an occupied slot replaces rather than fails, so a
                // location can be full of somebody else's rule. Where
                // the outgoing target is still known, the readback gets
                // the same field-by-field comparison as everything
                // else, and a slot holding an unrelated rule is not
                // reported: our rule is gone, which is what `steer off`
                // asked for, and alarming on it would send an operator
                // to `reconfigure` — which would delete the occupant
                // (review finding).
                //
                // Where it is NOT known — a restart whose config
                // dropped the port, so the state file is the only
                // record — ownership cannot be established either way.
                // Reported on occupancy there, and the health line says
                // "occupied" rather than claiming the traffic is ours:
                // silence is the worse error on the rollback path.
                Ok(()) if member.is_none() => {
                    if self.install_disowns(iface, *loc, &check.fs, &mut installed_consumed) {
                        tracing::debug!(
                            iface,
                            loc,
                            "a location this ledger names on an unsteered port holds a \
                             rule that is not ours; our rule is already gone"
                        );
                    } else {
                        stray.push((iface.clone(), *loc));
                    }
                }
                Ok(()) => {
                    let vf = member.expect("the arm above takes the non-member case");
                    let taken = consumed
                        .entry(iface.as_str())
                        .or_insert_with(|| vec![false; self.plan.rules.len()]);
                    // Candidates are stamped with the location being
                    // CHECKED, not the one planned: `matches` compares
                    // `location`, and on an adopted start the planner
                    // chose different slots by construction, so an
                    // unstamped expectation can never match.
                    let found = self.plan.rules.iter().enumerate().position(|(i, r)| {
                        !taken[i]
                            && audit_matches(
                                &RxFlowSpec {
                                    location: *loc,
                                    ..flow_spec(r, vf)
                                },
                                &check.fs,
                            )
                    });
                    match found {
                        Some(i) => taken[i] = true,
                        // Occupied by something this target does not
                        // ask for. WHICH complaint that is cannot be
                        // decided here: if a planned rule is left
                        // homeless, this is the slot where it should
                        // have been (drift — install it); if every
                        // planned rule found a home, nothing is absent
                        // and this is a surplus rule still diverting
                        // traffic (remove it). The allowlist shrinking
                        // produces the second, and calling it "missing"
                        // sent the operator to reinstall a rule that
                        // was not gone while removed-prefix traffic
                        // stayed in VPP (review finding). Paired up
                        // after the loop, when the homeless set is
                        // known.
                        //
                        // Unless the outgoing target can disown it
                        // outright, in which case it is not ours at
                        // all and neither complaint applies.
                        None => {
                            if self.install_disowns(iface, *loc, &check.fs, &mut installed_consumed)
                            {
                                tracing::debug!(
                                    iface,
                                    loc,
                                    "a location this ledger names holds a rule that is \
                                     neither this target's nor the last one's"
                                );
                            } else {
                                occupied
                                    .entry(iface.as_str())
                                    .or_default()
                                    .push((*loc, check.fs));
                            }
                        }
                    }
                }
                // Empty: ENOENT is how the driver answers for a location
                // holding nothing. Drift on a port the target steers;
                // on one it does not, it is the desired outcome — the
                // rule the ledger names is already gone.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if member.is_some() {
                        empty.entry(iface.as_str()).or_default().push(*loc);
                    }
                }
                // A read that failed says nothing about THIS rule, but
                // it must not erase what the other reads proved. The
                // early `return Err` here discarded every confirmed
                // entry, and the caller keeps its previous count on
                // `Err` — so an EIO on the last rule hid drift already
                // established on the first (review finding).
                Err(e) => {
                    read_errors.push(format!("loc {loc} on {iface}: {e}"));
                    // Tallied only for ports the target steers: the
                    // subtraction below is against THIS port's planned
                    // rules, and a port the target does not steer has
                    // none.
                    if member.is_some() {
                        *unreadable.entry(iface.as_str()).or_default() += 1;
                    }
                }
            }
        }

        // The other direction. Everything above walks the LEDGER and asks
        // whether the NIC still holds it, which cannot see a rule this
        // target asks for that was never installed at all — the shape a
        // restart produces whenever the allowlist grew while the daemon
        // was down: the state file names the old rules, the plan names
        // old and new, every old rule reads back clean, and the audit
        // reports nothing while the new prefix has no NIC rule anywhere.
        // That lasts as long as the adopted resync is deferred, which on
        // a box with no completeness authority is indefinitely (review
        // finding).
        //
        // Only reachable with a non-empty ledger — the caller skips the
        // audit otherwise — so this cannot fire on a port that has simply
        // never steered.
        for (iface, vf) in &self.ports {
            let taken = consumed.get(iface.as_str());
            let homeless: Vec<&SteerRule> = self
                .plan
                .rules
                .iter()
                .enumerate()
                .filter(|(i, _)| taken.is_none_or(|t| !t[*i]))
                .map(|(_, r)| r)
                .collect();
            let mut slots = empty.remove(iface.as_str()).unwrap_or_default();
            let mut occupants = occupied.remove(iface.as_str()).unwrap_or_default();
            let mut unread = unreadable.get(iface.as_str()).copied().unwrap_or(0);

            // Give every homeless rule an answer to "where should you
            // have been". Each answer is consumed, so one damaged rule
            // cannot count twice — once as the slot and once as the plan
            // entry that slot was holding.
            for rule in homeless {
                // A DAMAGED VERSION OF THIS RULE, first: same addresses,
                // same direction, same slot, but not what was asked for
                // — narrowed, or overwritten by a copy of its sibling.
                // That is one defect, and the useful location to name is
                // the one the damage is at.
                //
                // Identity is what makes this pairing legitimate, and
                // requiring it is the fix: popping ANY occupant let an
                // unrelated surplus rule stand in as the explanation. A
                // target moving from {A,B} to {B,C} then reported C
                // missing and said nothing about A still diverting
                // traffic the allowlist no longer covers — two
                // independent facts, one of them silently consumed by
                // the other (review finding).
                let damaged = occupants.iter().position(|(loc, got)| {
                    matches(
                        &RxFlowSpec {
                            location: *loc,
                            ..flow_spec(rule, *vf)
                        },
                        got,
                    )
                });
                if let Some(k) = damaged {
                    let (loc, _) = occupants.remove(k);
                    missing.push((iface.clone(), loc));
                } else if let Some(loc) = slots.pop() {
                    // An empty ledger slot says it plainly: something
                    // was installed here and is gone. No identity to
                    // check — an empty slot has no contents — so this
                    // stays a positional pairing.
                    missing.push((iface.clone(), loc));
                } else if unread > 0 {
                    // Explained by a read that failed: not established,
                    // and `unreadable` on the audit says so.
                    unread -= 1;
                } else {
                    // Nothing on this port can account for it, so it
                    // was never installed — the shape a restart
                    // produces when the allowlist GREW while the daemon
                    // was down. Named by its planned slot, the only
                    // location it has.
                    missing.push((iface.clone(), rule.location));
                }
            }
            // Occupants left over: rules the NIC still holds that this
            // target does not ask for, and that are not a damaged copy
            // of anything it does. The allowlist shrinking is what
            // produces them, and the remedy points the other way:
            // remove, not install.
            for (loc, _) in occupants {
                stray.push((iface.clone(), loc));
            }
        }

        if missing.is_empty() && stray.is_empty() && !read_errors.is_empty() {
            // Nothing proven and the NIC would not answer: report the
            // failure so the caller keeps its previous verdict rather
            // than adopting a clean one this audit never established.
            return Err(read_errors.join("; "));
        }
        // Both facts travel together. Confirmed drift used to be
        // returned alone with the read failures logged at debug, and the
        // caller reads any `Ok` as a complete pass — so it cleared its
        // "cannot verify" state and published the confirmed count as
        // current, while whatever sat behind the unreadable locations
        // stayed invisible (review finding). The count is a FLOOR
        // whenever this is `Some`.
        Ok(crate::runtime::SteeringAudit {
            missing,
            stray,
            unreadable: (!read_errors.is_empty()).then(|| read_errors.join("; ")),
        })
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
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));
        s.steer().expect("installs at 15 and 14");
        let after = McamBudget::for_ifaces(["eth0"]).expect("fake NIC answers");
        assert!(
            !after.free.contains(&15) && !after.free.contains(&14),
            "occupied slots must not be offered again: {:?}",
            after.free
        );
        assert_eq!(after.free.first(), Some(&13), "the next free one is next");
    }

    /// A CONFIGURED port with no rules to install refuses rather than
    /// reporting success.
    ///
    /// Somebody asked for this port to divert traffic and the allowlist
    /// or the MCAM budget produced nothing to divert it with. Neither
    /// `Ok` answers that: `SteerOutcome::Steered` becomes
    /// `Event::Steered` and puts the module in `Steered` with nothing
    /// steered, so health reports the offload carrying traffic it never
    /// saw; `SteerOutcome::NothingToSteer` retires the want and prints
    /// the line a deliberate `steer off` prints, hiding a broken
    /// allowlist behind it.
    ///
    /// The port list is what makes this the fault case — see
    /// [`a_reconcile_to_an_empty_target_clears_the_nic_and_says_so`] for
    /// the other emptiness, which is the operator's answer and not a
    /// fault.
    #[test]
    fn steering_a_configured_port_with_no_rules_is_refused() {
        use crate::runtime::Steering as _;
        let mut s = steering(vec![("eth0".into(), 0)], RuleSet::default());
        let e = s.steer().expect_err("must refuse");
        assert!(e.contains("nothing to steer"), "{e}");
        assert!(s.installed().is_empty());
    }

    /// The other emptiness: no port asks to steer, so the reconcile
    /// removes what a previous target left and reports that it holds
    /// nothing.
    ///
    /// `steer` is a reconcile, and an empty target is a legitimate
    /// thing to reconcile to — it is where `steer off` lands. Refusing
    /// it returned before the stale-rule removal, which is the only
    /// thing that could clear the leftovers, so the rules a refused
    /// `unsteer` had left in the NIC could never come out on their own.
    #[test]
    fn a_reconcile_to_an_empty_target_clears_the_nic_and_says_so() {
        use crate::runtime::Steering as _;
        sys::reset();

        let mut s = NtupleSteering::new(
            // Member AND steered at construction: these drive a
            // `steer off` retarget, so the port has to be acquired for
            // `vf_for` to answer once the target no longer names it.
            vec![("eth0".into(), 0)],
            vec![("eth0".into(), 0)],
            plan_for(&[[198, 18, 0, 0]]),
        );
        assert_eq!(
            s.steer().expect("installs"),
            SteerOutcome::Steered,
            "rules in the NIC is the other outcome, and the two must not be confusable"
        );
        assert!(
            !s.installed().is_empty(),
            "the fixture must install something"
        );

        // Every port `steer off`.
        s.retarget(Vec::new(), RuleSet::default());
        assert_eq!(
            s.steer()
                .expect("an empty target is reconcilable, not a fault"),
            SteerOutcome::NothingToSteer
        );
        assert!(s.installed().is_empty(), "the ledger must be empty too");
        assert!(
            sys::rule_table("eth0")
                .expect("the fake answers")
                .occupied
                .is_empty(),
            "the rules must be gone from the NIC, not merely forgotten by the ledger"
        );
    }

    /// A rule the NIC will not delete still refuses, even under an
    /// empty target.
    ///
    /// `NothingToSteer` is what releases the VF and retires the want, so
    /// it may only be said when the NIC really holds nothing. This is
    /// the half that must not be traded away to make the empty target
    /// reconcilable.
    #[test]
    fn an_empty_target_still_refuses_while_a_rule_will_not_come_out() {
        use crate::runtime::Steering as _;
        sys::reset();

        let mut s = NtupleSteering::new(
            // Member AND steered at construction: these drive a
            // `steer off` retarget, so the port has to be acquired for
            // `vf_for` to answer once the target no longer names it.
            vec![("eth0".into(), 0)],
            vec![("eth0".into(), 0)],
            plan_for(&[[198, 18, 0, 0]]),
        );
        s.steer().expect("installs");
        let stuck: Vec<u32> = s.installed().iter().map(|(_, loc)| *loc).collect();
        sys::wedge_delete(&stuck);

        s.retarget(Vec::new(), RuleSet::default());
        let e = s
            .steer()
            .expect_err("a rule that would not come out is still steering");
        assert!(e.contains("could not be removed"), "{e}");
        assert_eq!(
            s.installed().len(),
            stuck.len(),
            "what would not come out stays in the ledger, or the VF is released under it"
        );
    }

    /// A rule removed from the NIC behind our back is reported missing.
    ///
    /// Measured on the shadow 2026-08-11: `ethtool -N eth1 delete 12`
    /// while steered left the NIC holding three of four rules, and two
    /// minutes later `steering healthy` was still the answer — nothing
    /// polls the NIC, and only `VerifyPassed` re-emits `Action::Steer`,
    /// which does not recur in steady state. The traffic was fine (it
    /// falls back to the eBPF tier, which is where it belongs); what was
    /// lost was knowing.
    ///
    /// This is the detection half only. Repair stays manual — a plain
    /// `reconfigure` reinstalls the missing rule, because `steer` is a
    /// reconcile — so nothing here re-asserts anything, and a wrong
    /// answer costs a health line rather than a forwarding decision.
    #[test]
    fn a_rule_deleted_behind_our_back_is_reported_missing() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("steer installs");
        let installed = s.installed();
        assert!(!installed.is_empty(), "the fixture must install something");
        assert_eq!(
            audit(&s),
            Vec::new(),
            "a NIC that agrees with the ledger reports nothing missing"
        );

        // Exactly what the provisioning push did.
        let (iface, loc) = installed[0].clone();
        sys::remove_behind_back(&iface, loc);

        assert_eq!(
            audit(&s),
            vec![(iface, loc)],
            "a rule the NIC no longer holds must be reported, or the offload \
             goes silently partial with health green"
        );
        assert_eq!(
            s.installed().len(),
            installed.len(),
            "detection must not mutate the ledger — repair is a separate, \
             operator-triggered step"
        );
    }

    /// A location REPLACED by somebody else's rule is drift too.
    ///
    /// Occupancy was the first thing I checked, and it is not enough:
    /// an insert at an occupied location replaces rather than fails, so
    /// the slot stays in `GRXCLSRLALL` while our rule is gone —
    /// steering health would have read Healthy over a NIC matching
    /// traffic nobody asked it to (review finding). The audit compares
    /// the flow spec, which is the same check `insert` makes after
    /// every write.
    #[test]
    fn a_location_taken_over_by_another_rule_is_reported_missing() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("steer installs");
        let installed = s.installed();
        assert_eq!(
            audit(&s),
            Vec::new(),
            "our own rules must not read as drift"
        );

        let (iface, loc) = installed[0].clone();
        sys::replace_behind_back(&iface, loc);

        assert_eq!(
            audit(&s),
            vec![(iface, loc)],
            "a location still OCCUPIED but holding a different rule is not ours, \
             and occupancy alone cannot tell the difference"
        );
    }

    /// A rule NARROWED behind our back is drift, not a match.
    ///
    /// The subtle half of the same problem: the slot is occupied, the
    /// addresses are ours, the cookie is ours — but an added protocol
    /// mask means part of the traffic we believe is offloaded is not.
    /// Comparing only the address bytes (what `insert`'s tolerance
    /// permits, for good reasons of its own) reports this as fine.
    #[test]
    fn a_rule_narrowed_behind_our_back_is_reported_missing() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("steer installs");
        let installed = s.installed();
        let (iface, loc) = installed[0].clone();

        sys::narrow_behind_back(&iface, loc);

        assert_eq!(
            audit(&s),
            vec![(iface, loc)],
            "a rule carrying a constraint we never asked for is not ours — some \
             of the traffic we believe is steered no longer is"
        );
    }

    /// An ADOPTED rule is audited, even though its location is absent
    /// from the startup plan.
    ///
    /// This is the production path and it defeated the first version
    /// entirely. `McamBudget::from_table` excludes every occupied slot
    /// when planning, so on an adopted start the plan avoids our own
    /// rules and lands elsewhere; `bring_up` then restores the real
    /// locations from the state file. Keying the audit on "is there a
    /// planned rule AT this location" therefore skipped every inherited
    /// rule — for the whole adopted-resync deferral, which can hold
    /// indefinitely on a box with no completeness authority (review
    /// finding, and exactly the state the shadow sat in on
    /// 2026-08-11).
    #[test]
    fn an_adopted_rule_is_audited_though_the_plan_never_named_its_slot() {
        use crate::runtime::Steering as _;
        sys::reset();

        // The previous daemon: installs at the top of the table.
        let mut before = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        before.steer().expect("first run installs");
        let inherited = before.installed();
        assert!(!inherited.is_empty());

        // The new daemon plans against a table those rules occupy, so
        // it necessarily chooses different slots — then adopts.
        let budget = crate::steer::McamBudget::from_table(&rule_table("eth0").expect("table"));
        let allow = vec![IpPrefix::V4 {
            addr: [198, 18, 0, 0],
            prefix_len: 24,
        }];
        let fresh_plan = RuleSet::plan(&allow, budget).expect("fits");
        for r in &fresh_plan.rules {
            assert!(
                !inherited.iter().any(|(_, l)| *l == r.location),
                "the fixture must reproduce the real path: planned slot {} \
                 collides with an inherited one",
                r.location
            );
        }
        let mut after = steering(vec![("eth0".into(), 0)], fresh_plan);
        after.adopt_installed(inherited.clone());

        assert_eq!(
            audit(&after),
            Vec::new(),
            "inherited rules are present and ours; nothing is missing"
        );

        // NARROWED, not deleted — the case an ownership check cannot
        // see. A narrowed rule keeps our ring cookie, so accepting
        // adopted rules on the strength of the cookie reported this as
        // fine; the audit has to compare the spec against what the
        // current target asks for, at the location being checked.
        let (iface, loc) = inherited[0].clone();
        sys::narrow_behind_back(&iface, loc);
        assert_eq!(
            audit(&after),
            vec![(iface.clone(), loc)],
            "an inherited rule narrowed out of band must be reported — some of \
             the traffic we believe is offloaded no longer is"
        );

        // And outright deletion of an inherited rule, which is what the
        // hardware actually did on 2026-08-11.
        sys::remove_behind_back(&iface, loc);
        assert_eq!(
            audit(&after),
            vec![(iface, loc)],
            "an inherited rule deleted out of band must be reported, or the \
             audit is blind for the entire adopted deferral"
        );
    }

    /// Two locations holding the SAME rule is drift, not two matches.
    ///
    /// Each location was checked against "any planned rule"
    /// independently, so replacing our source-prefix rule with a second
    /// copy of the destination-prefix one passed twice — both slots
    /// matched something we plan — while source traffic had silently
    /// lost its offload (review finding). A planned rule can satisfy at
    /// most one location.
    #[test]
    fn one_planned_rule_cannot_account_for_two_locations() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("steer installs");
        let installed = s.installed();
        assert!(
            installed.len() >= 2,
            "the fixture needs at least two rules (src and dst) to duplicate one"
        );
        assert_eq!(audit(&s), Vec::new());

        // Overwrite the first slot with a copy of the second's rule.
        let (iface, victim) = installed[0].clone();
        let (_, survivor) = installed[1].clone();
        sys::duplicate_behind_back(&iface, survivor, victim);

        // Asserted as an INVARIANT, not as an identity. Once both slots
        // hold the same match they are indistinguishable by content, so
        // which of the two greedy matching leaves unaccounted is an
        // artifact of iteration order — pinning it would be asserting
        // the implementation rather than the property.
        let m = audit(&s);
        assert_eq!(
            m.len(),
            1,
            "exactly one slot must be unaccounted for — the prefix the \
             overwritten rule used to match is no longer offloaded: {m:?}"
        );
        assert!(
            m[0].0 == iface && (m[0].1 == victim || m[0].1 == survivor),
            "and it must be one of the two duplicated slots: {m:?}"
        );
    }

    /// A read that fails must not erase what the other reads proved.
    ///
    /// The audit used to `return Err` on the first unreadable location,
    /// discarding every confirmed entry — and the caller keeps its
    /// previous count on `Err`, so an EIO on one rule hid drift already
    /// established on another, for another 30 s (review finding).
    #[test]
    fn audit_keeps_confirmed_drift_when_a_later_read_fails() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("steer installs");
        let installed = s.installed();
        assert!(installed.len() >= 2);
        let (iface, gone) = installed[0].clone();
        let (_, unreadable) = installed[1].clone();

        sys::remove_behind_back(&iface, gone);
        sys::wedge_read(&[unreadable]);

        let a = s
            .missing_from_nic()
            .expect("proven drift survives an unreadable peer");
        assert_eq!(
            a.missing,
            vec![(iface.clone(), gone)],
            "the confirmed missing rule must be reported even though another \
             location could not be read"
        );
        // And the pass must say it was INCOMPLETE. Reporting the drift
        // alone made the caller clear its "cannot verify" state, so
        // health published a floor as a current count while whatever
        // sat behind the wedged location stayed invisible — the same
        // stale-answer-as-fresh mistake one level down (review finding).
        let why = a
            .unreadable
            .expect("a pass that could not read a location is not a complete one");
        assert!(
            why.contains(&unreadable.to_string()),
            "and it must name what it could not read: {why}"
        );

        // But an audit that proved NOTHING and could not read must fail
        // rather than report a clean NIC it never established.
        sys::reset();
        let mut s2 = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s2.steer().expect("installs");
        let all: Vec<u32> = s2.installed().iter().map(|(_, l)| *l).collect();
        sys::wedge_read(&all);
        assert!(
            s2.missing_from_nic().is_err(),
            "a wholly unreadable NIC must not read as clean — the caller keeps \
             its previous verdict on Err"
        );
    }

    /// A port dropped from the target is still audited, not ignored.
    ///
    /// `retarget` removes a port the config just set `steer off`, and
    /// the reconcile that would clear its rules can refuse at the
    /// completeness gate and never run. The audit skipped every ledger
    /// entry whose interface was no longer a member, so rules kept
    /// diverting traffic on a port an operator had asked to go quiet
    /// while steering read Healthy — on the rollback path, where getting
    /// traffic OFF a port is the entire point (review finding).
    #[test]
    fn a_port_the_target_no_longer_steers_is_still_audited() {
        use crate::runtime::Steering as _;
        sys::reset();
        let plan = plan_for(&[[198, 18, 0, 0]]);
        let mut s = steering(vec![("eth0".into(), 0), ("eth1".into(), 1)], plan.clone());
        s.steer().expect("steer installs on both ports");
        let a = s.missing_from_nic().expect("read the NIC");
        assert_eq!(a.missing, Vec::new());
        assert_eq!(a.stray, Vec::new(), "both ports are in the target");

        // `steer off` on eth1, and the reconciling steer never runs.
        s.retarget(vec![("eth0".into(), 0)], plan);

        let a = s.missing_from_nic().expect("read the NIC");
        assert_eq!(
            a.missing,
            Vec::new(),
            "eth0 still holds everything the target asks for"
        );
        let stray_ifaces: Vec<&str> = a.stray.iter().map(|(i, _)| i.as_str()).collect();
        assert!(
            !a.stray.is_empty() && stray_ifaces.iter().all(|i| *i == "eth1"),
            "the rules still steering the port that was turned off must be \
             reported — that is the rollback failing: {:?}",
            a.stray
        );

        // But a rule that is already GONE from a dropped port is the
        // desired outcome, not something to alarm about.
        for (iface, loc) in s.installed() {
            if iface == "eth1" {
                sys::remove_behind_back(&iface, loc);
            }
        }
        let a = s.missing_from_nic().expect("read the NIC");
        assert_eq!(
            a.stray,
            Vec::new(),
            "rules the NIC no longer holds are not still steering anything; \
             alarming on them would cry wolf on every successful unsteer"
        );
        assert_eq!(a.missing, Vec::new(), "and eth0 is still untouched");
    }

    /// A prefix dropped from the allowlist leaves SURPLUS, not absence.
    ///
    /// The two complaints point opposite ways and the audit collapsed
    /// them into one: after a shrink, every rule the target asks for is
    /// on the NIC and the leftovers are rules for prefixes nobody asked
    /// to steer any more. Calling those "missing" told an operator that
    /// target traffic had fallen back to the eBPF tier — the opposite of
    /// what happened, since the real problem is that removed-prefix
    /// traffic is *still* being diverted into VPP (review finding).
    ///
    /// Both routes into the shrink are covered: a restart that adopts a
    /// larger ledger than its plan (no outgoing target to compare
    /// against), and a live reconfigure whose reconcile has not run.
    #[test]
    fn prefixes_dropped_from_the_allowlist_are_surplus_not_absence() {
        use crate::runtime::Steering as _;
        sys::reset();
        let both = plan_for(&[[198, 18, 0, 0], [203, 0, 113, 0]]);
        let mut before = steering(vec![("eth0".into(), 0)], both);
        before.steer().expect("installs both prefixes");
        let inherited = before.installed();

        // THE RESTART: the config now allows one prefix, and the ledger
        // comes off disk with rules for two. Nothing to compare the
        // leftovers against but the plan itself.
        let one = plan_for(&[[198, 18, 0, 0]]);
        let owed = inherited.len() - one.rules.len();
        assert!(owed > 0, "the fixture must shrink the target");
        let mut after = steering(vec![("eth0".into(), 0)], one.clone());
        after.adopt_installed(inherited.clone());

        let a = after.missing_from_nic().expect("read the NIC");
        assert_eq!(
            a.missing,
            Vec::new(),
            "every rule this target asks for IS on the NIC — reporting absence \
             sends an operator to reinstall what was never gone: {:?}",
            a.missing
        );
        assert_eq!(
            a.stray.len(),
            owed,
            "and the rules for the dropped prefix are still steering traffic \
             into VPP, which is the complaint that needs making: {:?}",
            a.stray
        );

        // THE LIVE RECONFIGURE: same shrink, reached by retarget, so the
        // outgoing target is still known. Same verdict.
        let mut live = steering(
            vec![("eth0".into(), 0)],
            plan_for(&[[198, 18, 0, 0], [203, 0, 113, 0]]),
        );
        live.adopt_installed(inherited);
        live.retarget(vec![("eth0".into(), 0)], one);
        let a = live.missing_from_nic().expect("read the NIC");
        assert_eq!(a.missing, Vec::new(), "{:?}", a.missing);
        assert_eq!(a.stray.len(), owed, "{:?}", a.stray);
    }

    /// Swapping one prefix for another is TWO facts, not one.
    ///
    /// The pairing that stops a single damaged rule being counted twice
    /// was positional — any occupant could stand in as the explanation
    /// for any homeless rule — so a target moving from `{A,B}` to
    /// `{B,C}` reported C missing and silently consumed the independent
    /// fact that A's rules still divert traffic the allowlist no longer
    /// covers. One reconfigure fixes both, but an operator reading only
    /// half of it does not know the rollback side happened at all
    /// (review finding).
    ///
    /// Pairing now requires IDENTITY: an occupant explains a homeless
    /// rule only when it is a damaged copy of that same rule — same
    /// addresses, same direction, same slot.
    #[test]
    fn a_prefix_swapped_for_another_reports_both_sides() {
        use crate::runtime::Steering as _;
        sys::reset();
        const A: [u8; 4] = [198, 18, 0, 0];
        const B: [u8; 4] = [203, 0, 113, 0];
        const C: [u8; 4] = [192, 0, 2, 0];

        let mut before = steering(vec![("eth0".into(), 0)], plan_for(&[A, B]));
        before.steer().expect("installs A and B");
        let inherited = before.installed();
        let per_prefix = inherited.len() / 2;
        assert!(per_prefix > 0);

        // THE RESTART: config now says {B, C}; the NIC holds {A, B}.
        let mut after = steering(vec![("eth0".into(), 0)], plan_for(&[B, C]));
        after.adopt_installed(inherited.clone());

        let a = after.missing_from_nic().expect("read the NIC");
        assert_eq!(
            a.missing.len(),
            per_prefix,
            "C is not installed — that traffic is on the eBPF tier: {:?}",
            a.missing
        );
        assert_eq!(
            a.stray.len(),
            per_prefix,
            "AND A is still installed — that traffic is still going into VPP \
             though the allowlist no longer covers it. Reporting only the first \
             hides the rollback side entirely: {:?}",
            a.stray
        );
        // The two must not name the same slots: they are different
        // rules, in different places, needing opposite remedies.
        assert!(
            a.missing.iter().all(|m| !a.stray.contains(m)),
            "missing {:?} and stray {:?} describe distinct locations",
            a.missing,
            a.stray
        );

        // THE LIVE RECONFIGURE: same swap through retarget, so the
        // outgoing target is known. Same two facts.
        let mut live = steering(vec![("eth0".into(), 0)], plan_for(&[A, B]));
        live.adopt_installed(inherited);
        live.retarget(vec![("eth0".into(), 0)], plan_for(&[B, C]));
        let a = live.missing_from_nic().expect("read the NIC");
        assert_eq!(a.missing.len(), per_prefix, "{:?}", a.missing);
        assert_eq!(a.stray.len(), per_prefix, "{:?}", a.stray);
    }

    /// A SECOND refused reconfigure must not disown what is really there.
    ///
    /// The reference for "is this rule ours" was the outgoing target,
    /// recorded on every `retarget` — the last thing *intended*, not the
    /// last thing installed. `apply_steering` accepts another request
    /// from `Ready` after the completeness gate refuses one, so two
    /// reconfigures in a row left that reference describing a target
    /// which had never reached the NIC. The rules actually installed
    /// then matched nothing, were disowned as foreign, and left the
    /// audit altogether: not missing, not surplus, not mentioned
    /// (review finding).
    #[test]
    fn rules_survive_two_reconfigures_whose_reconcile_never_ran() {
        use crate::runtime::Steering as _;
        sys::reset();
        const A: [u8; 4] = [198, 18, 0, 0];
        const B: [u8; 4] = [203, 0, 113, 0];
        const C: [u8; 4] = [192, 0, 2, 0];

        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[A]));
        s.steer()
            .expect("A is installed, and confirmed by readback");
        let installed = s.installed().len();
        assert!(installed > 0);

        // Two reconfigures, neither reconciled — the supervisor refused
        // both at the completeness gate, so `steer` never ran again and
        // the NIC still holds A.
        s.retarget(vec![("eth0".into(), 0)], plan_for(&[B]));
        s.retarget(vec![("eth0".into(), 0)], plan_for(&[C]));

        let a = s.missing_from_nic().expect("read the NIC");
        assert_eq!(
            a.stray.len(),
            installed,
            "A's rules are still on the NIC and the allowlist no longer covers \
             them — disowning them as foreign because an intermediate target \
             never matched loses the fact entirely: {:?}",
            a.stray
        );
        assert_eq!(
            a.missing.len(),
            s.plan.rules.len(),
            "and C, which was never installed, is still absent: {:?}",
            a.missing
        );
    }

    /// An UNRELATED rule at a dropped port's slot is not our steering.
    ///
    /// Occupancy is not ownership — the mistake the member path was
    /// burned by twice, reintroduced on the non-member path the moment
    /// it was added: an insert at an occupied location replaces rather
    /// than fails, so a slot the ledger names can hold somebody else's
    /// rule while ours is already gone. Reporting that raises a rollback
    /// alarm that is not happening, and sends an operator to
    /// `reconfigure`, which would delete the occupant (review finding).
    ///
    /// Checkable here because the outgoing target is still known: the
    /// readback gets the same field-by-field comparison as everything
    /// else.
    #[test]
    fn an_unrelated_rule_on_a_dropped_port_is_not_our_steering() {
        use crate::runtime::Steering as _;
        sys::reset();
        let plan = plan_for(&[[198, 18, 0, 0]]);
        let mut s = steering(vec![("eth0".into(), 0), ("eth1".into(), 1)], plan.clone());
        s.steer().expect("steer installs on both ports");
        let eth1: Vec<(String, u32)> = s
            .installed()
            .into_iter()
            .filter(|(i, _)| i == "eth1")
            .collect();
        assert!(eth1.len() >= 2, "the fixture needs two rules on eth1");

        // `steer off` on eth1, reconcile refused — the round-13 state.
        s.retarget(vec![("eth0".into(), 0)], plan);
        assert_eq!(
            s.missing_from_nic().expect("read").stray.len(),
            eth1.len(),
            "our own rules on the dropped port are still ours, and still there"
        );

        // Now somebody else takes one of those slots. Our rule at it is
        // gone, which is what `steer off` asked for.
        let (iface, taken) = eth1[0].clone();
        sys::replace_behind_back(&iface, taken);

        let a = s.missing_from_nic().expect("read");
        assert!(
            !a.stray.contains(&(iface.clone(), taken)),
            "a slot holding a rule that is not ours is not our steering — \
             reporting it would raise a rollback alarm for traffic nobody is \
             diverting, and point `reconfigure` at somebody else's rule: {:?}",
            a.stray
        );
        assert_eq!(
            a.stray.len(),
            eth1.len() - 1,
            "and the rules that ARE still ours must still be reported: {:?}",
            a.stray
        );
    }

    /// A ledger naming one rule twice does not make a correct NIC drift.
    ///
    /// The state file is JSON on disk, so what comes back is not
    /// necessarily what this code wrote — an older build appended to the
    /// ledger unconditionally (fixed in #128, see `steer`), and a file
    /// can be edited. The audit gives one planned rule to one location,
    /// so a second copy of an entry found nothing left to match and
    /// reported drift against a NIC holding exactly what was asked for.
    /// Degraded forever, too: `reconfigure` cannot clear it, because a
    /// duplicate is not stale — it is in the desired set — and the
    /// insert loop's set-check only declines to add a third copy.
    #[test]
    fn a_ledger_naming_one_rule_twice_is_read_as_naming_it_once() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut before = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        before.steer().expect("first run installs");
        let inherited = before.installed();
        assert!(inherited.len() >= 2);

        // What an older build's ledger looks like: the supervisor
        // re-asserts steering on a VPP it believes steered, and every
        // re-assert appended the same slots again.
        let mut doubled = inherited.clone();
        doubled.extend(inherited.iter().cloned());

        let mut after = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        after.adopt_installed(doubled);
        assert_eq!(
            after.installed(),
            inherited,
            "a location exists once on the NIC, so the ledger holds it once — and \
             this is also what gets persisted back"
        );
        assert_eq!(
            audit(&after),
            Vec::new(),
            "a NIC holding exactly what was asked for must not read as drift; a \
             false alarm with no remedy is what teaches an operator to ignore the line"
        );

        // The dedup must not cost the audit its teeth: real drift behind
        // a duplicated ledger is still drift.
        let (iface, loc) = inherited[0].clone();
        sys::remove_behind_back(&iface, loc);
        assert_eq!(
            audit(&after),
            vec![(iface, loc)],
            "and a rule that really is gone must still be reported"
        );
    }

    /// A rule the target ASKS FOR that the NIC never got is missing too.
    ///
    /// The audit walked the ledger and asked the NIC about each entry,
    /// which cannot see the other direction: restart a steered daemon
    /// after the allowlist gained a prefix and the state file names only
    /// the old rules. Every one of them reads back clean, so the audit
    /// reported nothing while the new prefix had no NIC rule anywhere —
    /// steering Healthy over an offload the config says is bigger than
    /// it is, for as long as the adopted resync stays deferred (review
    /// finding).
    #[test]
    fn a_rule_the_target_asks_for_that_was_never_installed_is_reported_missing() {
        use crate::runtime::Steering as _;
        sys::reset();

        // The previous daemon steered one prefix.
        let mut before = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        before.steer().expect("first run installs");
        let inherited = before.installed();
        assert!(!inherited.is_empty());

        // This one starts with a grown allowlist and adopts what the
        // state file names — the old rules only.
        let grown = plan_for(&[[198, 18, 0, 0], [203, 0, 113, 0]]);
        let owed = grown.rules.len() - inherited.len();
        assert!(
            owed > 0,
            "the fixture must ask for more rules than were inherited"
        );
        let mut after = steering(vec![("eth0".into(), 0)], grown);
        after.adopt_installed(inherited.clone());

        let m = audit(&after);
        assert_eq!(
            m.len(),
            owed,
            "every planned rule with no rule on the NIC must be reported, or the \
             newly allowlisted prefix is unsteered with health green: {m:?}"
        );
        assert!(
            m.iter().all(|e| !inherited.contains(e)),
            "the inherited rules ARE on the NIC — reporting them would be \
             counting the same absence twice: {m:?}"
        );

        // And a deleted inherited rule is one more absence, not a
        // replacement for one already counted.
        let (iface, loc) = inherited[0].clone();
        sys::remove_behind_back(&iface, loc);
        let m = audit(&after);
        assert_eq!(
            m.len(),
            owed + 1,
            "drift and an uninstalled rule are separate absences: {m:?}"
        );
        assert!(
            m.contains(&(iface, loc)),
            "including the slot the NIC no longer holds: {m:?}"
        );
    }

    /// A read that FAILS must not be turned into an uninstalled rule.
    ///
    /// The second direction counts planned rules that no readback
    /// accounted for — and a location the NIC would not answer for
    /// accounts for nothing. Subtracting them is what keeps a wedged
    /// read from manufacturing drift the audit never established, which
    /// is the same "unverifiable treated as unconstrained" mistake this
    /// audit has now made twice.
    #[test]
    fn a_wedged_read_is_not_reported_as_an_uninstalled_rule() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("steer installs");
        let installed = s.installed();
        assert!(installed.len() >= 2);
        let (_, wedged) = installed[1].clone();

        sys::wedge_read(&[wedged]);

        let e = s
            .missing_from_nic()
            .expect_err("nothing was proven and a location could not be read");
        assert!(
            e.contains(&wedged.to_string()),
            "the answer must be 'cannot verify', naming the location, rather than \
             a fabricated missing rule: {e}"
        );
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
    ///
    /// The rules are installed for real rather than adopted onto an
    /// empty NIC: removal reads each location back first, and a slot
    /// holding nothing never reaches the delete at all.
    #[test]
    fn a_rule_that_will_not_delete_stays_recorded() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));
        s.steer().expect("installs");
        let locs: Vec<u32> = s.installed().iter().map(|(_, l)| *l).collect();
        assert_eq!(locs.len(), 2, "the fixture needs two rules");
        sys::wedge_delete(&locs);

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

    /// A stranger's rule at a claimed slot is NOT deleted by `unsteer`.
    ///
    /// The removal path addressed a location and asked the NIC nothing,
    /// while the audit thirty lines away was careful about exactly this:
    /// an insert at an occupied slot replaces rather than fails, so a
    /// location the ledger names can hold somebody else's classifier
    /// rule. Teardown then removed it and broke its traffic — and unlike
    /// a wrong health line, that is not recoverable by reading (review
    /// finding).
    ///
    /// `unsteer` still returns `Ok`, and that is the point rather than a
    /// concession: `Ok` releases the VF, and what makes the release safe
    /// is that nothing at that location steers into the VF. The
    /// stranger's rule does not.
    #[test]
    fn a_stranger_at_a_claimed_slot_survives_unsteer() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("installs");
        let installed = s.installed();
        assert!(installed.len() >= 2, "the fixture needs two rules");

        let (iface, taken) = installed[0].clone();
        sys::replace_behind_back(&iface, taken);

        s.unsteer()
            .expect("nothing of ours is left steering into the VF");
        assert_eq!(
            sys::rules(),
            vec![(iface.clone(), taken)],
            "the rule that is not ours must still be in the NIC — deleting it \
             breaks traffic this module never claimed"
        );
        assert!(
            s.installed().is_empty(),
            "and the ledger must stop claiming a slot that is not ours, or a \
             later `detach --all` reads the record and deletes it after all"
        );
    }

    /// The same protection on `steer`'s stale removal — the reconfigure
    /// path, which is what the runbook sends an operator to first.
    #[test]
    fn a_stranger_at_a_stale_slot_survives_a_reconfigure() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(
            vec![("eth0".into(), 0)],
            plan_for(&[[10, 0, 0, 0], [10, 1, 0, 0]]),
        );
        s.steer().expect("installs four");
        assert_eq!(sys::rules().len(), 4);

        // Down to one prefix: 13 and 12 are stale. Somebody else takes 13
        // while the daemon is not looking.
        s.retarget(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));
        sys::replace_behind_back("eth0", 13);
        s.steer().expect("reconciles");

        assert!(
            sys::rules().contains(&("eth0".to_string(), 13)),
            "the stale slot held a rule that was not ours, and a reconfigure \
             must not remove it: {:?}",
            sys::rules()
        );
        assert!(
            !sys::rules().contains(&("eth0".to_string(), 12)),
            "while the stale rule that really was ours still comes out: {:?}",
            sys::rules()
        );
        let mut ledger = s.installed();
        ledger.sort();
        assert_eq!(
            ledger,
            vec![("eth0".to_string(), 14), ("eth0".to_string(), 15)],
            "and the ledger names the new target only"
        );
    }

    /// A rule we do NOT recognise that steers into our VF still comes out.
    ///
    /// This is why removal keys on the ring cookie rather than on
    /// `audit_matches`: the audit would disown this rule, and disowning
    /// it here would hand back a VF with MCAM still pointing into it —
    /// the blackhole `remove_all`'s contract exists to prevent, reached
    /// through the ownership check meant to make removal safer.
    #[test]
    fn a_rule_into_our_vf_comes_out_even_when_it_is_not_recognisable() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("installs");
        let (iface, taken) = s.installed()[0].clone();

        // Our slot, our VF, a match nothing here would have asked for.
        sys::replace_behind_back_targeting(&iface, taken, ring_cookie(0));

        s.unsteer().expect("removes");
        assert!(
            sys::rules().is_empty(),
            "a rule steering into the VF must not survive the VF's release, \
             whether or not we can prove we installed it: {:?}",
            sys::rules()
        );
        assert!(s.installed().is_empty());
    }

    /// A restart keeps the protection: the reference removal needs is the
    /// VF, and that comes from the config rather than from the state file.
    ///
    /// The state file records locations and nothing about what they hold,
    /// so `installed_as` is `None` here and no content comparison is
    /// available — which is precisely the case where the ledger's claim
    /// is least trustworthy, because it has survived a window in which
    /// this module was not running.
    #[test]
    fn an_adopted_ledger_still_leaves_a_stranger_alone() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut before = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        before.steer().expect("the previous process installs");
        let inherited = before.installed();
        assert!(!inherited.is_empty());

        let mut after = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        after.adopt_installed(inherited.clone());
        assert!(
            after.installed_as.is_none(),
            "the fixture must reproduce the restart: nothing to compare a \
             readback against"
        );

        let (iface, taken) = inherited[0].clone();
        sys::replace_behind_back(&iface, taken);

        after
            .unsteer()
            .expect("ours are gone; the VF is safe to release");
        assert_eq!(
            sys::rules(),
            vec![(iface, taken)],
            "the stranger's rule survives an adopted teardown too: {:?}",
            sys::rules()
        );
    }

    /// A location the NIC will not describe is not deleted on a guess.
    ///
    /// Both halves of the removal contract point the same way here — do
    /// not delete a rule that may not be ours, and do not report a VF
    /// safe to release — so this fails loudly and the entry stays
    /// recorded. The cost is a teardown that needs an operator; the
    /// alternative is the blind delete the readback exists to end.
    #[test]
    fn a_location_that_cannot_be_read_is_not_deleted_blind() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("installs");
        let installed = s.installed();
        assert!(installed.len() >= 2);
        let (iface, wedged) = installed[0].clone();

        sys::wedge_read(&[wedged]);

        let e = s
            .unsteer()
            .expect_err("an unreadable location is not a removed one");
        assert!(
            e.contains(&wedged.to_string()),
            "the refusal must name the location an operator has to settle: {e}"
        );
        assert_eq!(
            sys::rules(),
            vec![(iface.clone(), wedged)],
            "the unreadable rule is untouched, and every readable one came out"
        );
        assert_eq!(
            s.installed(),
            vec![(iface, wedged)],
            "and it stays on the record, or nothing can ever remove it"
        );
    }

    /// A rule aimed at another QUEUE of our VF still comes out.
    ///
    /// The cookie is two fields — VF in bits 32..40, queue index in bits
    /// 0..32 — and everything this module installs leaves the queue at
    /// zero, so comparing the whole `u64` agrees with the VF field for
    /// our own rules and looks correct. It is not: `vf 0 queue 3` reads
    /// as somebody else's target, so the rule was left in place and
    /// `unsteer` reported the VF safe to release with MCAM still
    /// pointing into it — the blackhole the readback was added to
    /// prevent, arriving through the ownership check that prevents it
    /// (review finding on this PR).
    #[test]
    fn a_rule_on_another_queue_of_our_vf_still_comes_out() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        s.steer().expect("installs");
        let (iface, taken) = s.installed()[0].clone();

        // Our VF, queue 3 — a cookie nothing here would ever write.
        let other_queue = ring_cookie(0) | 3;
        assert_ne!(
            other_queue,
            ring_cookie(0),
            "the fixture must differ from ours"
        );
        assert_eq!(
            ring_cookie_vf(other_queue),
            ring_cookie_vf(ring_cookie(0)),
            "and must still name our VF, or it tests nothing"
        );
        sys::replace_behind_back_targeting(&iface, taken, other_queue);

        s.unsteer().expect("removes");
        assert!(
            sys::rules().is_empty(),
            "anything steering into the VF must be gone before the VF is \
             released, whichever of its queues it names: {:?}",
            sys::rules()
        );
    }

    /// The VF field is what identifies the target, and `0` is the PF.
    #[test]
    fn the_cookie_splits_into_a_vf_and_a_queue() {
        assert_eq!(ring_cookie_vf(ring_cookie(0)), 1, "VF 0 is field 1");
        assert_eq!(ring_cookie_vf(ring_cookie(1)), 2);
        // A queue index in the low half does not change the VF.
        assert_eq!(ring_cookie_vf(ring_cookie(0) | 0xFFFF_FFFF), 1);
        // The PF's own queues carry VF field 0, which is no VF of ours.
        assert_eq!(ring_cookie_vf(0), 0);
        assert_eq!(ring_cookie_vf(7), 0);
    }

    /// A port turned `steer off` ACROSS A RESTART still knows its VF.
    ///
    /// The hardest case for ownership and the one the rollback path
    /// depends on: `bring_up` builds the steering target from the
    /// `steer on` ports only, and `installed_as` is set solely by a
    /// successful steer in this process — so after a restart that turned
    /// a port off, neither can say which VF the port's inherited rules
    /// would have to name. Removal fell through to deleting by location,
    /// which is the blind delete this all exists to end, surviving in
    /// the case where the ledger's claim has been unattended longest
    /// (review finding on this PR).
    ///
    /// `members` answers it, because it is an acquisition fact rather
    /// than a steering one.
    #[test]
    fn a_steer_off_port_after_a_restart_can_still_attribute_its_slots() {
        use crate::runtime::Steering as _;
        sys::reset();
        let plan = plan_for(&[[198, 18, 0, 0]]);
        let mut before = steering(vec![("eth0".into(), 0), ("eth1".into(), 0)], plan.clone());
        before
            .steer()
            .expect("the previous process steers both ports");
        let inherited = before.installed();
        let eth1: Vec<(String, u32)> = inherited
            .iter()
            .filter(|(i, _)| i == "eth1")
            .cloned()
            .collect();
        assert!(eth1.len() >= 2, "the fixture needs two rules on eth1");

        // The restart: eth1 is now `steer off`, so it is a member but
        // not a steering target, and nothing was installed this process.
        let mut after = NtupleSteering::new(
            vec![("eth0".into(), 0), ("eth1".into(), 0)],
            vec![("eth0".into(), 0)],
            plan,
        );
        after.adopt_installed(inherited);
        assert!(
            after.installed_as.is_none(),
            "the fixture must be a restart"
        );

        // Somebody took one of eth1's slots while the daemon was down.
        let (iface, taken) = eth1[0].clone();
        sys::replace_behind_back(&iface, taken);
        let (_, ours) = eth1[1].clone();

        after.unsteer().expect("ours come out");
        assert!(
            sys::rules().contains(&(iface.clone(), taken)),
            "the rule that is not ours must survive a rollback teardown on a \
             port we no longer steer: {:?}",
            sys::rules()
        );
        assert!(
            !sys::rules().contains(&(iface, ours)),
            "while the inherited rule that IS ours still comes out: {:?}",
            sys::rules()
        );
    }

    /// With no VF known for the interface, removal is by location, as it
    /// always was.
    ///
    /// Nothing can attribute the occupant — there is no cookie to compare
    /// against — and the entry is in the ledger because this module put
    /// it there. `packetframe detach --all` used to arrive here; it now
    /// passes the state file's ports, so this is the residual case and
    /// the tradeoff is documented rather than silent.
    #[test]
    fn a_ledger_entry_with_no_known_vf_is_removed_by_location() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut before = steering(vec![("eth0".into(), 0)], plan_for(&[[198, 18, 0, 0]]));
        before.steer().expect("installs");
        let inherited = before.installed();

        // No ports at all: the shape a caller with only a location list has.
        let mut blind = NtupleSteering::new(Vec::new(), Vec::new(), RuleSet::default());
        blind.adopt_installed(inherited);
        blind.unsteer().expect("removes what the ledger names");
        assert!(sys::rules().is_empty());
        assert!(blind.installed().is_empty());
    }

    /// Rules the controller wiped behind the ledger's back are already
    /// unsteered — `unsteer` must say so, not fail. The failing version
    /// wedged the whole adopted pipeline: the ledger stayed populated,
    /// every re-requested unsteer failed on the same ENOENT, and the
    /// deferred reconciliation waited forever on an acknowledgement
    /// that could never come (review finding on the pre-dump gate).
    #[test]
    fn vanished_rules_count_as_removed_not_as_failures() {
        use crate::runtime::Steering as _;
        sys::reset();
        let mut s = steering(vec![("eth0".into(), 0)], RuleSet::default());
        // The state file remembers two rules; the NIC holds neither.
        s.adopt_installed(vec![("eth0".into(), 1024), ("eth0".into(), 1025)]);

        s.unsteer()
            .expect("absent rules satisfy the removal's postcondition");
        assert!(
            s.installed().is_empty(),
            "nothing may stay recorded when nothing is steering"
        );
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
        let mut s = steering(vec![("eth0".into(), 0)], plan);
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

    /// The audit's findings, asserting the pass read everything it was
    /// asked about.
    ///
    /// Every fixture below drives a NIC that answers, so an incomplete
    /// pass means the fixture broke — and `missing` alone cannot say so,
    /// which is the whole reason the audit reports both facts.
    fn audit(s: &NtupleSteering) -> Vec<(String, u32)> {
        use crate::runtime::Steering as _;
        let a = s.missing_from_nic().expect("read the NIC");
        assert_eq!(
            a.unreadable, None,
            "this fixture answers every readback; an incomplete pass here is a \
             broken test, not a finding"
        );
        a.missing
    }

    /// A steering object whose members and steering target are the same
    /// set — the ordinary case, where every acquired port is steered.
    ///
    /// The cases that differ pass the two lists explicitly, because that
    /// difference is the thing under test.
    fn steering(ports: Vec<(String, u32)>, plan: RuleSet) -> NtupleSteering {
        NtupleSteering::new(ports.clone(), ports, plan)
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
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));

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
        let mut s = steering(vec![("eth0".into(), 0)], plan_for(&[[10, 0, 0, 0]]));

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
        let mut s = steering(
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
        let mut s = steering(
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
        let mut s = steering(
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
    /// The rollback that could not finish: `steer off`, a removal the
    /// NIC refuses, a crash, and a restart — and the module clears it
    /// on the next convergence instead of retrying a no-op forever.
    ///
    /// Every step of this is deliberate behaviour somewhere else in the
    /// subsystem, which is what made it a trap rather than a bug in any
    /// one place:
    ///
    /// - a refused `unsteer` keeps its rules in `installed` and
    ///   `steered` true, so the VF stays withheld while MCAM may still
    ///   point at it ([`NtupleSteering::remove_all`]);
    /// - a death while `steered` re-arms `steer_wanted`, so a restart
    ///   nobody watched does not silently leave the offload off;
    /// - `VerifyPassed` therefore re-steers, because
    ///   `steer_intended()` is true.
    ///
    /// Composed, they used to meet a `steer` that refused an empty
    /// target *before* its stale-rule removal — so the one action that
    /// could have cleared the rules returned an error instead, on every
    /// convergence, while the rules went on diverting traffic for a
    /// port the operator had asked to stop steering.
    ///
    /// Drives the real supervisor and the real executor, because that
    /// composition IS the defect: each half is correct alone.
    #[test]
    fn a_refused_unsteer_is_cleared_by_the_next_convergence() {
        use crate::executor::{execute, Effects};
        use crate::process::Disposition;
        use crate::runtime::Steering as _;
        use crate::supervisor::{Event, State, Supervisor};

        /// The steering half of [`Effects`] over a real
        /// `NtupleSteering`. Everything else succeeds silently: this
        /// test is about which rules are in the NIC, and a process
        /// double that could fail would only add ways to not reach the
        /// convergence.
        struct SteeringOnly(NtupleSteering);

        impl Effects for SteeringOnly {
            fn steer(&mut self) -> Result<SteerOutcome, String> {
                self.0.steer()
            }
            fn restore_steer(&mut self) -> Result<SteerOutcome, String> {
                self.0.steer()
            }
            fn unsteer(&mut self) -> Result<(), String> {
                self.0.unsteer()
            }
            fn steering_in_place(&self) -> bool {
                !self.0.installed().is_empty()
            }
            fn spawn(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn kill(&mut self) -> Disposition {
                Disposition::SafeToRelease
            }
            fn attach_devices(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn start_resync(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn start_verify(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn abort_convergence(&mut self) {}
            fn arm_backoff(&mut self, _d: std::time::Duration) {}
            fn release_resources(&mut self) -> Result<(), String> {
                Ok(())
            }
        }

        /// Apply one event and feed the executor's events back until
        /// the two settle, exactly as the driver's tick does.
        fn settle(sup: &mut Supervisor, fx: &mut SteeringOnly, event: Event) {
            let mut pending = vec![event];
            for _ in 0..16 {
                if pending.is_empty() {
                    return;
                }
                let mut next = Vec::new();
                for e in pending.drain(..) {
                    let actions = sup.on(e);
                    next.extend(execute(&actions, fx).events);
                }
                pending = next;
            }
            panic!("the supervisor/executor seam did not settle");
        }

        fn nic_holds(iface: &str) -> Vec<u32> {
            sys::rule_table(iface).expect("the fake answers").occupied
        }

        sys::reset();
        let mut fx = SteeringOnly(NtupleSteering::new(
            vec![("eth4".into(), 0)],
            vec![("eth4".into(), 0)],
            plan_for(&[[198, 18, 0, 0]]),
        ));
        let mut sup = Supervisor::new();

        // 1. Converge, then the operator moves the canary lever. The
        //    machine never steers a first attach on its own.
        settle(&mut sup, &mut fx, Event::StartRequested);
        settle(&mut sup, &mut fx, Event::Spawned);
        settle(&mut sup, &mut fx, Event::ApiUp);
        settle(&mut sup, &mut fx, Event::SyncComplete);
        settle(&mut sup, &mut fx, Event::VerifyPassed);
        settle(&mut sup, &mut fx, Event::SteerRequested);
        assert_eq!(sup.state(), State::Steered);
        let steered_locs = nic_holds("eth4");
        assert!(!steered_locs.is_empty(), "the fixture must steer something");

        // 2. `steer off` on every port, `packetframe reconfigure` — and
        //    the NIC refuses to delete what it holds.
        sys::wedge_delete(&steered_locs);
        fx.0.retarget(Vec::new(), RuleSet::default());
        settle(&mut sup, &mut fx, Event::UnsteerRequested);
        assert!(
            sup.is_steered(),
            "a removal the NIC refused must keep `steered` true, or the VF is released \
             under live rules"
        );
        assert_eq!(
            nic_holds("eth4"),
            steered_locs,
            "the rules are still there — that is the premise of the rest of this test"
        );

        // 3. VPP dies. The teardown unsteers first, is refused again,
        //    and the death re-arms the want because rules remain.
        settle(&mut sup, &mut fx, Event::ProcessExited { status: None });
        assert_eq!(sup.state(), State::Backoff);
        assert!(sup.is_steered() && sup.steer_intended());

        // 4. The NIC stops refusing. Nothing about the module changed —
        //    a UniFi provisioning push or a firmware event clears
        //    classifier state underneath us, and by design the module
        //    is supposed to reconcile whatever it finds.
        sys::wedge_delete(&[]);

        // 5. The replacement comes up and verifies. THIS is where the
        //    module used to re-enter its refusal: `steer_intended()` is
        //    true, so `VerifyPassed` emits `Action::Steer`, and the
        //    target is empty.
        settle(&mut sup, &mut fx, Event::BackoffElapsed);
        settle(&mut sup, &mut fx, Event::Spawned);
        settle(&mut sup, &mut fx, Event::ApiUp);
        settle(&mut sup, &mut fx, Event::SyncComplete);
        settle(&mut sup, &mut fx, Event::VerifyPassed);

        assert!(
            nic_holds("eth4").is_empty(),
            "the leftover rules must be GONE from the NIC: they divert traffic for a \
             port the operator turned off, and no convergence after this one will look \
             again. Still holding {:?}",
            nic_holds("eth4")
        );
        assert!(
            fx.0.installed().is_empty(),
            "and gone from the ledger, which is what the state file persists and what \
             releasing the VF is gated on"
        );
        assert!(
            !sup.is_steered(),
            "`steered` must clear, or every later teardown keeps withholding the VF for \
             rules that are not there"
        );
        assert!(
            !sup.steer_intended(),
            "the want must retire too. `Unsteered` alone leaves it set — correct on the \
             adopted path, wrong here — and the module would sit Degraded on `steering \
             intended but not in place` with an empty config and nothing left to do"
        );
        assert_eq!(sup.state(), State::Ready, "membership without steering");
    }
}
