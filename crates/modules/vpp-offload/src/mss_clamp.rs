//! VPP's TCP MSS clamp on a VLAN's L3 interfaces (`mss-clamp vlan`).
//!
//! The fast path clamps MSS in XDP, and a frame the NIC steers to VPP never
//! reaches XDP. VPP's `mss_clamp` plugin clamps per interface: an `RX`
//! feature on `ip4-unicast` / `ip6-unicast` (routed input) and a `TX`
//! feature on `ip4-output` / `ip6-output` (routed output), lowering the MSS
//! option of any SYN or SYN-ACK above the value. A VLAN's hosts reach VPP
//! through its L3 interface (the BVI on a bridged VLAN, otherwise the
//! member's subinterface, or the VF for a port's untagged VLAN), and
//! traffic to them leaves through it, so both directions on it cover every
//! flow to or from the VLAN. Design: `docs/runbooks/vpp-mss-clamp-design.md`.
//!
//! The plugin's messages are optional at the handshake
//! ([`crate::vpp_api::transport::OPTIONAL_MESSAGES`]): a VPP without it
//! attaches, and only a configured clamp is reported as not in place, which
//! holds the first steer.

use std::collections::{BTreeMap, HashSet};
use std::sync::RwLock;

use crate::vpp_api::generated::{
    MssClampDetails, MssClampEnableDisable, MssClampEnableDisableReply, MssClampGet,
    MssClampGetReply,
};
use crate::vpp_api::transport::{Transport, TransportError};

/// Every message this module speaks, for [`Transport::unavailable`].
pub const MESSAGES: &[&str] = &[
    "mss_clamp_enable_disable",
    "mss_clamp_enable_disable_reply",
    "mss_clamp_get",
    "mss_clamp_get_reply",
    "mss_clamp_details",
];

/// `MSS_CLAMP_DIR_RX | MSS_CLAMP_DIR_TX`.
pub const DIR_RX_TX: u8 = 0x3;

/// `VNET_API_ERROR_EAGAIN`: a `_get` page ended early; ask again from its
/// cursor.
const EAGAIN: i32 = -165;

/// One `mss-clamp vlan` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanClamp {
    pub vlan: u16,
    pub ip4: Option<u16>,
    pub ip6: Option<u16>,
}

/// The configured `mss-clamp vlan` set, which `reconfigure` publishes
/// into and the engine reads on each pass. Hot: a change is applied at
/// the next VLAN refresh.
#[derive(Debug, Default)]
pub struct MssClamps(RwLock<Vec<VlanClamp>>);

impl MssClamps {
    pub fn new(clamps: Vec<VlanClamp>) -> Self {
        Self(RwLock::new(clamps))
    }

    /// Replace the whole set. The module is the only writer.
    pub fn publish(&self, clamps: Vec<VlanClamp>) {
        *self.0.write().expect("mss-clamp lock") = clamps;
    }

    pub fn get(&self) -> Vec<VlanClamp> {
        self.0.read().expect("mss-clamp lock").clone()
    }
}

/// What one interface holds, or should: per family, the directions and
/// the value. A family with no direction holds no value; VPP reports an
/// unset one as `0xffff`, so it is normalised to 0 here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Clamp {
    pub dir4: u8,
    pub mss4: u16,
    pub dir6: u8,
    pub mss6: u16,
}

impl Clamp {
    pub const OFF: Clamp = Clamp {
        dir4: 0,
        mss4: 0,
        dir6: 0,
        mss6: 0,
    };

    /// Both directions, at these values.
    pub fn both_ways(ip4: Option<u16>, ip6: Option<u16>) -> Self {
        Self {
            dir4: if ip4.is_some() { DIR_RX_TX } else { 0 },
            mss4: ip4.unwrap_or(0),
            dir6: if ip6.is_some() { DIR_RX_TX } else { 0 },
            mss6: ip6.unwrap_or(0),
        }
    }

    fn normalised(self) -> Self {
        Self {
            dir4: self.dir4,
            mss4: if self.dir4 == 0 { 0 } else { self.mss4 },
            dir6: self.dir6,
            mss6: if self.dir6 == 0 { 0 } else { self.mss6 },
        }
    }

    /// Merge two VLANs' wants on one interface: the lower value per
    /// family. Only an untagged VF could be asked twice, and only by a
    /// config naming two VLANs untagged on one port, which the kernel
    /// does not allow; this keeps the answer safe regardless.
    fn merge(self, other: Self) -> Self {
        let pick = |d1: u8, m1: u16, d2: u8, m2: u16| match (d1 != 0, d2 != 0) {
            (true, true) => (d1 | d2, m1.min(m2)),
            (true, false) => (d1, m1),
            (false, true) => (d2, m2),
            (false, false) => (0, 0),
        };
        let (dir4, mss4) = pick(self.dir4, self.mss4, other.dir4, other.mss4);
        let (dir6, mss6) = pick(self.dir6, self.mss6, other.dir6, other.mss6);
        Self {
            dir4,
            mss4,
            dir6,
            mss6,
        }
    }
}

/// Where each VLAN's clamp goes: `(vlan, interfaces)`, as the engine
/// resolves them. A VLAN with no interface yet (a `vlans all` trunk that
/// has not seen it) has an empty list.
pub type Targets = Vec<(VlanClamp, Vec<u32>)>;

/// The interfaces' wanted state, from [`Targets`].
pub fn desired(targets: &Targets) -> BTreeMap<u32, Clamp> {
    let mut out: BTreeMap<u32, Clamp> = BTreeMap::new();
    for (c, ifs) in targets {
        let want = Clamp::both_ways(c.ip4, c.ip6);
        for i in ifs {
            out.entry(*i)
                .and_modify(|w| *w = w.merge(want))
                .or_insert(want);
        }
    }
    out
}

/// What to send: every wanted interface whose held state differs, and
/// every OWNED interface holding a clamp nobody wants any more (a line
/// removed by a reload). An interface this module does not own is never
/// touched, whatever it holds: somebody else configured it.
pub fn plan(
    want: &BTreeMap<u32, Clamp>,
    held: &BTreeMap<u32, Clamp>,
    owned: &HashSet<u32>,
) -> Vec<(u32, Clamp)> {
    let mut out = Vec::new();
    for (i, w) in want {
        let have = held.get(i).copied().unwrap_or(Clamp::OFF).normalised();
        if have != w.normalised() {
            out.push((*i, *w));
        }
    }
    for (i, h) in held {
        if !want.contains_key(i) && owned.contains(i) && h.normalised() != Clamp::OFF {
            out.push((*i, Clamp::OFF));
        }
    }
    out
}

/// Every interface VPP clamps, as it reports them.
pub fn read(t: &mut Transport) -> Result<BTreeMap<u32, Clamp>, TransportError> {
    let mut out = BTreeMap::new();
    let mut cursor = 0u32;
    // Bounded: a cursor that never ends would otherwise hold the loop.
    for _ in 0..64 {
        let (items, end): (Vec<MssClampDetails>, MssClampGetReply) = t.get_page(MssClampGet {
            context: 0,
            cursor,
            sw_if_index: u32::MAX,
        })?;
        for d in items {
            out.insert(
                d.sw_if_index,
                Clamp {
                    dir4: d.ipv4_direction,
                    mss4: d.ipv4_mss,
                    dir6: d.ipv6_direction,
                    mss6: d.ipv6_mss,
                }
                .normalised(),
            );
        }
        if end.retval != EAGAIN {
            return Ok(out);
        }
        cursor = end.cursor;
    }
    Ok(out)
}

/// Set one interface's clamp. `Ok(Err(retval))` is VPP refusing it, with
/// the connection intact.
pub fn set(
    t: &mut Transport,
    sw_if_index: u32,
    c: Clamp,
) -> Result<Result<(), i32>, TransportError> {
    let reply: MssClampEnableDisableReply = t.request(MssClampEnableDisable {
        context: 0,
        sw_if_index,
        ipv4_mss: c.mss4,
        ipv6_mss: c.mss6,
        ipv4_direction: c.dir4,
        ipv6_direction: c.dir6,
    })?;
    Ok(if reply.retval == 0 {
        Ok(())
    } else {
        Err(reply.retval)
    })
}

/// Whether every configured clamp is in place, for the first-steer gate
/// and the status row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClampStatus {
    /// Configured VLANs.
    pub configured: Vec<u16>,
    /// Configured VLANs not (yet) clamped, each with why.
    pub missing: Vec<(u16, String)>,
}

impl ClampStatus {
    pub fn in_place(&self) -> bool {
        self.missing.is_empty()
    }

    /// Whether the last pass had any clamp configured, so a reload that
    /// removed every line still clears what the previous one set.
    pub fn had_any(&self) -> bool {
        !self.configured.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_sends_only_differences_and_clears_only_owned_interfaces() {
        let c1360 = Clamp::both_ways(Some(1360), None);
        let targets: Targets = vec![(
            VlanClamp {
                vlan: 1337,
                ip4: Some(1360),
                ip6: None,
            },
            vec![200, 101],
        )];
        let want = desired(&targets);
        let owned: HashSet<u32> = [200, 101, 102].into();

        // Nothing held: both interfaces set.
        assert_eq!(
            plan(&want, &BTreeMap::new(), &owned),
            vec![(101, c1360), (200, c1360)]
        );
        // Held as wanted (VPP's unset v6 value is 0xffff): nothing sent.
        let mut held = BTreeMap::new();
        for i in [101, 200] {
            held.insert(
                i,
                Clamp {
                    dir4: DIR_RX_TX,
                    mss4: 1360,
                    dir6: 0,
                    mss6: 0xffff,
                },
            );
        }
        assert!(plan(&want, &held, &owned).is_empty());
        // A stale owned clamp is cleared; a stranger's is left alone; a
        // changed value is re-sent.
        held.insert(102, c1360);
        held.insert(7, c1360);
        held.insert(200, Clamp::both_ways(Some(1400), None));
        assert_eq!(
            plan(&want, &held, &owned),
            vec![(200, c1360), (102, Clamp::OFF)]
        );
        // RX only is not what was asked for.
        held.insert(200, Clamp { dir4: 1, ..c1360 });
        assert_eq!(plan(&want, &held, &owned)[0], (200, c1360));
    }

    #[test]
    fn two_wants_on_one_interface_take_the_lower_value() {
        let targets: Targets = vec![
            (
                VlanClamp {
                    vlan: 1,
                    ip4: Some(1400),
                    ip6: None,
                },
                vec![3],
            ),
            (
                VlanClamp {
                    vlan: 2,
                    ip4: Some(1360),
                    ip6: Some(1340),
                },
                vec![3],
            ),
        ];
        assert_eq!(
            desired(&targets)[&3],
            Clamp::both_ways(Some(1360), Some(1340))
        );
    }
}
