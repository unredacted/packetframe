//! `steer-capacity`: asking a port's NIC for a bigger ntuple table.
//!
//! The 16-rule table measured on 2026-08-05 is not the hardware. It is
//! the octeontx2 driver's default allocation (`OTX2_DEFAULT_FLOWCOUNT`),
//! carved from a classifier pool every port and VF shares — 2,048
//! entries, ~1,700 of them free on the reference NIC. The driver
//! exposes the per-port count as the runtime devlink parameter
//! `mcam_count`; raising it to 256 and then inserting at `loc 40`, which
//! the default table refuses, was verified on hardware (2026-09-24).
//!
//! Three driver facts shape this module (`otx2_devlink.c`,
//! `otx2_flows.c`):
//!
//! - **A resize is refused while the port holds any ntuple rule.** So it
//!   is attach-time work, done before the first steer, and a port that
//!   already carries rules keeps the table it has.
//! - **A resize frees the current entries and allocates anew, and a
//!   short allocation is silent** — the table simply becomes whatever
//!   the pool gave. It can come back SMALLER than it started, which is
//!   why a short result puts the old size back.
//! - **The value is runtime-only**: a reboot or driver reload returns
//!   the port to the default. Hence asserting it at every attach, rather
//!   than as hand state an operator sets once (the fleet wipes hand
//!   state; see the runbook).
//!
//! The table the NIC reports AFTERWARDS is the only answer. The
//! steering budget is still built from that read, exactly as before
//! this existed, so nothing here can make the planner believe in a slot
//! the NIC does not have. A NIC without the parameter keeps its table
//! and the attach log says why.

use crate::ntuple::RuleTable;

/// The octeontx2 devlink parameter holding a port's ntuple table size.
pub const PARAM: &str = "mcam_count";

/// The NIC reads and writes [`ensure`] needs — a seam so the decision
/// logic is testable without an rvu port, and non-Linux builds never
/// pretend.
pub trait CapacityControl {
    /// The port's ntuple table as the driver reports it.
    fn table(&self, iface: &str) -> Result<RuleTable, String>;
    /// `Ok` with the parameter's current value when the port's driver
    /// exposes it; `Err` naming why not otherwise.
    fn adjustable(&self, iface: &str) -> Result<u16, String>;
    /// Ask the driver for `count` table entries.
    fn set(&self, iface: &str, count: u16) -> Result<(), String>;
}

/// What asking one port for `want` entries came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The table already holds at least `want`; nothing was written.
    Enough { size: u32 },
    /// The table grew to at least `want`.
    Raised { from: u32, to: u32 },
    /// The pool gave fewer than `want`. `now` is the table after any
    /// restore — never smaller than `from` unless the restore failed,
    /// which `describe` says.
    Short { from: u32, want: u16, now: u32 },
    /// Rules are installed, and the driver will not resize under them.
    RulesInstalled { size: u32, rules: usize },
    /// The port's driver offers no way to resize.
    NotAdjustable { size: u32, why: String },
    /// The table could not be read, or the resize itself failed.
    Failed { why: String },
}

impl Outcome {
    /// Whether the port ended up with the capacity asked for.
    pub fn met(&self) -> bool {
        matches!(self, Self::Enough { .. } | Self::Raised { .. })
    }

    /// One attach-log line.
    pub fn describe(&self, iface: &str, want: u16) -> String {
        match self {
            Self::Enough { size } => {
                format!("{iface}: ntuple table holds {size} ≥ steer-capacity {want}")
            }
            Self::Raised { from, to } => {
                format!("{iface}: ntuple table raised {from} → {to} (steer-capacity {want})")
            }
            Self::Short { from, want, now } => format!(
                "{iface}: asked for {want} ntuple entries, the shared classifier pool gave \
                 fewer; the table is {now} (was {from}){}. The steering budget is whatever \
                 the table holds — check `npc/mcam_info` in debugfs for what is left",
                if now < from {
                    " — SMALLER than before, and putting the old size back failed"
                } else {
                    ""
                }
            ),
            Self::RulesInstalled { size, rules } => format!(
                "{iface}: {rules} ntuple rule(s) already installed, and the driver will not \
                 resize a table holding rules; it stays at {size} below steer-capacity {want} \
                 until the port is unsteered and the module restarted"
            ),
            Self::NotAdjustable { size, why } => {
                format!("{iface}: ntuple table stays at {size} below steer-capacity {want}: {why}")
            }
            Self::Failed { why } => format!("{iface}: steer-capacity {want} not applied: {why}"),
        }
    }
}

/// Bring one port's ntuple table up to `want`, if its driver can.
///
/// Never shrinks a table, never resizes one holding rules (the driver
/// would refuse anyway, and the refusal is clearer from here), and
/// judges the result by reading the table back rather than by the
/// write's return — the driver's short allocation is silent.
pub fn ensure(ctl: &dyn CapacityControl, iface: &str, want: u16) -> Outcome {
    let before = match ctl.table(iface) {
        Ok(t) => t,
        Err(why) => return Outcome::Failed { why },
    };
    let want32 = u32::from(want);
    if before.size >= want32 {
        return Outcome::Enough { size: before.size };
    }
    if !before.occupied.is_empty() {
        return Outcome::RulesInstalled {
            size: before.size,
            rules: before.occupied.len(),
        };
    }
    if let Err(why) = ctl.adjustable(iface) {
        return Outcome::NotAdjustable {
            size: before.size,
            why,
        };
    }
    let written = ctl.set(iface, want);
    let after = match ctl.table(iface) {
        Ok(t) => t.size,
        Err(e) => {
            return Outcome::Failed {
                why: format!(
                    "the table could not be read back after the resize ({e}); its size is \
                     unknown"
                ),
            }
        }
    };
    if after >= want32 {
        return Outcome::Raised {
            from: before.size,
            to: after,
        };
    }
    // Short or failed. A resize frees before it allocates, so the table
    // may now be smaller than the default it started from — put that
    // back rather than leave the port worse off than no directive.
    let now = if after < before.size {
        restore(ctl, iface, before.size).unwrap_or(after)
    } else {
        after
    };
    match written {
        Ok(()) => Outcome::Short {
            from: before.size,
            want,
            now,
        },
        Err(e) => Outcome::Failed {
            why: format!("{e}; the table is {now} (was {})", before.size),
        },
    }
}

/// Best-effort return to `size`; the size actually read back, if any.
fn restore(ctl: &dyn CapacityControl, iface: &str, size: u32) -> Option<u32> {
    let size16 = u16::try_from(size).ok()?;
    ctl.set(iface, size16).ok()?;
    ctl.table(iface).ok().map(|t| t.size)
}

/// The table `iface` will offer once attach has applied `want`.
///
/// For `packetframe feasibility`, which runs before attach and must not
/// write anything: a port whose driver can resize, holding no rules, is
/// planned at the requested size. The pool may still give fewer at
/// attach — the probe's detail says the size is requested, and attach
/// plans against the real read either way.
pub fn predicted_table(
    ctl: &dyn CapacityControl,
    iface: &str,
    want: Option<u16>,
) -> Result<(RuleTable, bool), String> {
    let table = ctl.table(iface)?;
    let Some(want) = want else {
        return Ok((table, false));
    };
    let want32 = u32::from(want);
    if table.size >= want32 || !table.occupied.is_empty() || ctl.adjustable(iface).is_err() {
        return Ok((table, false));
    }
    Ok((
        RuleTable {
            size: want32,
            occupied: table.occupied,
        },
        true,
    ))
}

/// The production control: the ntuple ioctls for the table, devlink for
/// the parameter.
pub struct Live;

impl CapacityControl for Live {
    fn table(&self, iface: &str) -> Result<RuleTable, String> {
        crate::ntuple::rule_table(iface)
    }

    fn adjustable(&self, iface: &str) -> Result<u16, String> {
        let (bus, dev) = device_handle(iface)?;
        sys::param_get_u16(&bus, &dev, PARAM)
    }

    fn set(&self, iface: &str, count: u16) -> Result<(), String> {
        let (bus, dev) = device_handle(iface)?;
        sys::param_set_u16(&bus, &dev, PARAM, count)
    }
}

/// devlink names a device by bus and bus address (`pci`,
/// `0002:04:00.0`), which sysfs gives for any netdev backed by a
/// device: the `device` link's target is the address, and its
/// `subsystem` link's target is the bus.
fn device_handle(iface: &str) -> Result<(String, String), String> {
    let base = std::path::Path::new("/sys/class/net")
        .join(iface)
        .join("device");
    let name = |p: &std::path::Path| -> Result<String, String> {
        let target = std::fs::read_link(p).map_err(|e| format!("{}: {e}", p.display()))?;
        target
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .ok_or_else(|| format!("{}: unexpected link target", p.display()))
    };
    let dev = name(&base).map_err(|e| {
        format!("{iface} has no backing device, so devlink has nothing to address ({e})")
    })?;
    let bus = name(&base.join("subsystem"))?;
    Ok((bus, dev))
}

// ----- Generic netlink, by hand -------------------------------------------
//
// Hand-rolled for the same reason `fdb.rs` is: this crate has no async
// runtime, and two request/ack exchanges at attach do not earn a
// generic-netlink dependency. The encoders are pure and platform-free so
// the byte layout is tested on every host; only the socket is Linux.

/// The wire format, platform-free so every host tests it; only the
/// socket in `sys` is Linux, which leaves these unreached elsewhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod wire {
    /// Constants from `include/uapi/linux/netlink.h`, `genetlink.h` and
    /// `devlink.h` (v5.15 — the fleet kernel; these values are ABI).
    pub(super) mod abi {
        pub const NLMSG_HDRLEN: usize = 16;
        pub const GENL_HDRLEN: usize = 4;
        pub const NLMSG_ERROR: u16 = 2;
        pub const NLMSG_DONE: u16 = 3;
        pub const NLM_F_REQUEST: u16 = 0x1;
        pub const NLM_F_ACK: u16 = 0x4;
        pub const NLA_F_NESTED: u16 = 1 << 15;
        pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

        pub const GENL_ID_CTRL: u16 = 0x10;
        pub const CTRL_CMD_GETFAMILY: u8 = 3;
        pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
        pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

        pub const DEVLINK_GENL_NAME: &str = "devlink";
        pub const DEVLINK_GENL_VERSION: u8 = 1;
        pub const DEVLINK_CMD_PARAM_GET: u8 = 38;
        pub const DEVLINK_CMD_PARAM_SET: u8 = 39;
        pub const DEVLINK_ATTR_BUS_NAME: u16 = 1;
        pub const DEVLINK_ATTR_DEV_NAME: u16 = 2;
        pub const DEVLINK_ATTR_PARAM: u16 = 80;
        pub const DEVLINK_ATTR_PARAM_NAME: u16 = 81;
        pub const DEVLINK_ATTR_PARAM_TYPE: u16 = 83;
        pub const DEVLINK_ATTR_PARAM_VALUES_LIST: u16 = 84;
        pub const DEVLINK_ATTR_PARAM_VALUE: u16 = 85;
        pub const DEVLINK_ATTR_PARAM_VALUE_DATA: u16 = 86;
        pub const DEVLINK_ATTR_PARAM_VALUE_CMODE: u16 = 87;
        /// `DEVLINK_PARAM_TYPE_U16`, defined as `NLA_U16`.
        pub const DEVLINK_PARAM_TYPE_U16: u8 = 2;
        pub const DEVLINK_PARAM_CMODE_RUNTIME: u8 = 0;
    }

    pub(super) fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    /// Append one netlink attribute, padded to 4 bytes.
    pub(super) fn put_attr(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(payload);
        buf.resize(buf.len() + (align4(len) - len), 0);
    }

    /// A NUL-terminated string attribute, as the kernel's `NLA_NUL_STRING`
    /// and `NLA_STRING` policies both accept.
    pub(super) fn put_str(buf: &mut Vec<u8>, ty: u16, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        put_attr(buf, ty, &v);
    }

    /// One generic-netlink request: `nlmsghdr` + `genlmsghdr` + attributes.
    pub(super) fn genl_message(
        family: u16,
        flags: u16,
        seq: u32,
        cmd: u8,
        version: u8,
        attrs: &[u8],
    ) -> Vec<u8> {
        let len = abi::NLMSG_HDRLEN + abi::GENL_HDRLEN + attrs.len();
        let mut m = Vec::with_capacity(len);
        m.extend_from_slice(&(len as u32).to_ne_bytes());
        m.extend_from_slice(&family.to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid: the kernel fills ours in
        m.push(cmd);
        m.push(version);
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(attrs);
        m
    }

    /// Walk a run of attributes as `(type, payload)`, flags masked off.
    /// Stops at the first malformed length rather than reading past it.
    pub(super) fn attrs(mut b: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        while b.len() >= 4 {
            let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
            let ty = u16::from_ne_bytes([b[2], b[3]]) & abi::NLA_TYPE_MASK;
            if len < 4 || len > b.len() {
                break;
            }
            out.push((ty, &b[4..len]));
            b = &b[align4(len).min(b.len())..];
        }
        out
    }

    /// What one reply datagram run said to request `seq`.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(super) struct Reply {
        /// Attribute runs of every data message, genl header stripped.
        pub(super) data: Vec<Vec<u8>>,
        /// `Some(0)` for an ACK, `Some(-errno)` for an error; `None` while
        /// the final word has not arrived.
        pub(super) status: Option<i32>,
    }

    /// Fold one received buffer into `reply`, keeping only messages for
    /// `seq`.
    pub(super) fn absorb(reply: &mut Reply, mut b: &[u8], seq: u32) {
        while b.len() >= abi::NLMSG_HDRLEN {
            let len = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
            let ty = u16::from_ne_bytes([b[4], b[5]]);
            let mseq = u32::from_ne_bytes([b[8], b[9], b[10], b[11]]);
            if len < abi::NLMSG_HDRLEN || len > b.len() {
                break;
            }
            let body = &b[abi::NLMSG_HDRLEN..len];
            if mseq == seq {
                match ty {
                    abi::NLMSG_ERROR if body.len() >= 4 => {
                        reply.status =
                            Some(i32::from_ne_bytes([body[0], body[1], body[2], body[3]]));
                    }
                    abi::NLMSG_DONE => reply.status = Some(reply.status.unwrap_or(0)),
                    _ if body.len() >= abi::GENL_HDRLEN => {
                        reply.data.push(body[abi::GENL_HDRLEN..].to_vec());
                    }
                    _ => {}
                }
            }
            b = &b[align4(len).min(b.len())..];
        }
    }

    /// `CTRL_ATTR_FAMILY_ID` out of a `CTRL_CMD_GETFAMILY` reply.
    pub(super) fn family_id(reply: &Reply) -> Option<u16> {
        reply.data.iter().find_map(|run| {
            attrs(run)
                .into_iter()
                .find(|(ty, p)| *ty == abi::CTRL_ATTR_FAMILY_ID && p.len() >= 2)
                .map(|(_, p)| u16::from_ne_bytes([p[0], p[1]]))
        })
    }

    /// The runtime-cmode `u16` out of a `DEVLINK_CMD_PARAM_GET` reply:
    /// `PARAM { VALUES_LIST { VALUE { CMODE, DATA } … } }`.
    pub(super) fn runtime_u16(reply: &Reply) -> Option<u16> {
        for run in &reply.data {
            for (ty, param) in attrs(run) {
                if ty != abi::DEVLINK_ATTR_PARAM {
                    continue;
                }
                for (ty, list) in attrs(param) {
                    if ty != abi::DEVLINK_ATTR_PARAM_VALUES_LIST {
                        continue;
                    }
                    for (ty, value) in attrs(list) {
                        if ty != abi::DEVLINK_ATTR_PARAM_VALUE {
                            continue;
                        }
                        let fields = attrs(value);
                        let runtime = fields.iter().any(|(t, p)| {
                            *t == abi::DEVLINK_ATTR_PARAM_VALUE_CMODE
                                && p.first() == Some(&abi::DEVLINK_PARAM_CMODE_RUNTIME)
                        });
                        let data = fields.iter().find_map(|(t, p)| {
                            (*t == abi::DEVLINK_ATTR_PARAM_VALUE_DATA && p.len() >= 2)
                                .then(|| u16::from_ne_bytes([p[0], p[1]]))
                        });
                        if let (true, Some(v)) = (runtime, data) {
                            return Some(v);
                        }
                    }
                }
            }
        }
        None
    }

    /// The attributes naming one device's parameter — shared by GET and SET.
    pub(super) fn param_attrs(bus: &str, dev: &str, param: &str) -> Vec<u8> {
        let mut a = Vec::new();
        put_str(&mut a, abi::DEVLINK_ATTR_BUS_NAME, bus);
        put_str(&mut a, abi::DEVLINK_ATTR_DEV_NAME, dev);
        put_str(&mut a, abi::DEVLINK_ATTR_PARAM_NAME, param);
        a
    }

    /// A runtime `u16` PARAM_SET body.
    pub(super) fn param_set_attrs(bus: &str, dev: &str, param: &str, value: u16) -> Vec<u8> {
        let mut a = param_attrs(bus, dev, param);
        put_attr(
            &mut a,
            abi::DEVLINK_ATTR_PARAM_TYPE,
            &[abi::DEVLINK_PARAM_TYPE_U16],
        );
        put_attr(
            &mut a,
            abi::DEVLINK_ATTR_PARAM_VALUE_DATA,
            &value.to_ne_bytes(),
        );
        put_attr(
            &mut a,
            abi::DEVLINK_ATTR_PARAM_VALUE_CMODE,
            &[abi::DEVLINK_PARAM_CMODE_RUNTIME],
        );
        a
    }

    /// Name an errno the way this module's readers need it.
    pub(super) fn errno_text(what: &str, status: i32) -> String {
        let e = std::io::Error::from_raw_os_error(-status);
        let hint = match -status {
            libc::EINVAL | libc::EOPNOTSUPP => {
                " — the driver has no such parameter, or refused the value (it also refuses \
                 while any ntuple rule is installed)"
            }
            libc::ENODEV => " — no devlink instance for this device",
            libc::EPERM => " — needs CAP_NET_ADMIN",
            _ => "",
        };
        format!("{what}: {e}{hint}")
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::wire::{
        abi, absorb, family_id, genl_message, param_attrs, param_set_attrs, put_str,
    };
    use super::wire::{errno_text, runtime_u16, Reply};
    use netlink_sys::{protocols::NETLINK_GENERIC, Socket, SocketAddr};

    /// One request, answered: every data message for it plus the
    /// closing ACK or error. Always asks for the ACK, so the loop has a
    /// definite end on success as well as failure.
    fn exchange(
        socket: &Socket,
        family: u16,
        seq: u32,
        cmd: u8,
        version: u8,
        attrs: &[u8],
    ) -> Result<Reply, String> {
        let msg = genl_message(
            family,
            abi::NLM_F_REQUEST | abi::NLM_F_ACK,
            seq,
            cmd,
            version,
            attrs,
        );
        socket
            .send(&msg, 0)
            .map_err(|e| format!("netlink send: {e}"))?;
        let mut reply = Reply::default();
        let mut buf = vec![0u8; 16 * 1024];
        while reply.status.is_none() {
            let n = socket
                .recv(&mut &mut buf[..], 0)
                .map_err(|e| format!("netlink recv: {e}"))?;
            absorb(&mut reply, &buf[..n], seq);
        }
        Ok(reply)
    }

    /// A connected generic-netlink socket and devlink's family id.
    fn devlink() -> Result<(Socket, u16), String> {
        let mut socket =
            Socket::new(NETLINK_GENERIC).map_err(|e| format!("netlink socket: {e}"))?;
        // Runs on the attach path; an unbounded receive would be a hang
        // there with nothing to cancel it.
        crate::fdb::bound_recv(&socket)?;
        socket
            .bind_auto()
            .map_err(|e| format!("netlink bind: {e}"))?;
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|e| format!("netlink connect: {e}"))?;
        let mut a = Vec::new();
        put_str(&mut a, abi::CTRL_ATTR_FAMILY_NAME, abi::DEVLINK_GENL_NAME);
        let reply = exchange(
            &socket,
            abi::GENL_ID_CTRL,
            1,
            abi::CTRL_CMD_GETFAMILY,
            1,
            &a,
        )?;
        match (reply.status, family_id(&reply)) {
            (Some(0), Some(id)) => Ok((socket, id)),
            (Some(s), _) if s < 0 => Err(errno_text("resolving the devlink netlink family", s)),
            _ => Err("resolving the devlink netlink family: no family id in the reply".into()),
        }
    }

    pub(super) fn param_get_u16(bus: &str, dev: &str, param: &str) -> Result<u16, String> {
        let (socket, family) = devlink()?;
        let reply = exchange(
            &socket,
            family,
            2,
            abi::DEVLINK_CMD_PARAM_GET,
            abi::DEVLINK_GENL_VERSION,
            &param_attrs(bus, dev, param),
        )?;
        match reply.status {
            Some(s) if s < 0 => Err(errno_text(&format!("devlink {bus}/{dev} `{param}`"), s)),
            _ => runtime_u16(&reply).ok_or_else(|| {
                format!("devlink {bus}/{dev} `{param}`: no runtime u16 value in the reply")
            }),
        }
    }

    pub(super) fn param_set_u16(
        bus: &str,
        dev: &str,
        param: &str,
        value: u16,
    ) -> Result<(), String> {
        let (socket, family) = devlink()?;
        let reply = exchange(
            &socket,
            family,
            3,
            abi::DEVLINK_CMD_PARAM_SET,
            abi::DEVLINK_GENL_VERSION,
            &param_set_attrs(bus, dev, param, value),
        )?;
        match reply.status {
            Some(0) => Ok(()),
            Some(s) => Err(errno_text(
                &format!("devlink {bus}/{dev} `{param}` = {value}"),
                s,
            )),
            None => unreachable!("exchange returns only once a status arrived"),
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    pub(super) fn param_get_u16(_: &str, _: &str, _: &str) -> Result<u16, String> {
        Err("devlink is Linux-only".into())
    }
    pub(super) fn param_set_u16(_: &str, _: &str, _: &str, _: u16) -> Result<(), String> {
        Err("devlink is Linux-only".into())
    }
}

#[cfg(test)]
mod tests {
    use super::wire::*;
    use super::*;
    use std::cell::RefCell;

    /// A port whose driver behaves like otx2: refuses resizes under
    /// rules, frees before allocating, and gives at most `pool`.
    struct FakePort {
        size: RefCell<u32>,
        rules: usize,
        adjustable: bool,
        pool: u32,
        writes: RefCell<Vec<u16>>,
        set_errors: bool,
    }

    impl FakePort {
        fn new(size: u32) -> Self {
            Self {
                size: RefCell::new(size),
                rules: 0,
                adjustable: true,
                pool: 2048,
                writes: RefCell::new(Vec::new()),
                set_errors: false,
            }
        }
    }

    impl CapacityControl for FakePort {
        fn table(&self, _: &str) -> Result<RuleTable, String> {
            Ok(RuleTable {
                size: *self.size.borrow(),
                occupied: (0..self.rules as u32).collect(),
            })
        }
        fn adjustable(&self, _: &str) -> Result<u16, String> {
            if self.adjustable {
                Ok(*self.size.borrow() as u16)
            } else {
                Err("no such parameter".into())
            }
        }
        fn set(&self, _: &str, count: u16) -> Result<(), String> {
            self.writes.borrow_mut().push(count);
            assert_eq!(
                self.rules, 0,
                "the driver refuses this; ensure must not try"
            );
            *self.size.borrow_mut() = u32::from(count).min(self.pool);
            if self.set_errors {
                return Err("mailbox timeout".into());
            }
            Ok(())
        }
    }

    #[test]
    fn a_default_table_is_raised_and_judged_by_the_read_back() {
        let port = FakePort::new(16);
        assert_eq!(
            ensure(&port, "eth4", 64),
            Outcome::Raised { from: 16, to: 64 }
        );
        assert_eq!(*port.writes.borrow(), vec![64]);
    }

    #[test]
    fn a_table_already_big_enough_is_left_alone() {
        let port = FakePort::new(128);
        assert_eq!(ensure(&port, "eth4", 64), Outcome::Enough { size: 128 });
        assert!(
            port.writes.borrow().is_empty(),
            "never shrinks, never rewrites"
        );
    }

    #[test]
    fn a_port_holding_rules_is_not_resized() {
        // An adopted, steered VPP after a daemon restart: the rules are
        // live traffic. The driver refuses anyway; asking would only
        // turn a clear reason into a mailbox errno.
        let mut port = FakePort::new(16);
        port.rules = 6;
        assert_eq!(
            ensure(&port, "eth4", 64),
            Outcome::RulesInstalled { size: 16, rules: 6 }
        );
        assert!(port.writes.borrow().is_empty());
    }

    #[test]
    fn a_driver_without_the_parameter_keeps_its_table() {
        let mut port = FakePort::new(16);
        port.adjustable = false;
        let got = ensure(&port, "eth4", 64);
        assert!(
            matches!(got, Outcome::NotAdjustable { size: 16, .. }),
            "{got:?}"
        );
        assert!(!got.met());
        assert!(port.writes.borrow().is_empty());
    }

    #[test]
    fn a_short_pool_is_reported_not_believed() {
        // The driver's short allocation is silent: the write succeeds
        // and the table is simply smaller than asked.
        let mut port = FakePort::new(16);
        port.pool = 40;
        assert_eq!(
            ensure(&port, "eth4", 64),
            Outcome::Short {
                from: 16,
                want: 64,
                now: 40
            }
        );
    }

    #[test]
    fn a_table_that_came_back_smaller_is_put_back() {
        // Freed 16, and the pool had only 8 left to give. Leaving 8
        // would make the directive worse than not writing it.
        let port = FakePort {
            pool: 8,
            ..FakePort::new(16)
        };
        let got = ensure(&port, "eth4", 64);
        assert_eq!(*port.writes.borrow(), vec![64, 16]);
        assert_eq!(
            got,
            Outcome::Short {
                from: 16,
                want: 64,
                now: 8
            },
            "an 8-entry pool cannot hold 16 either, and the outcome says so"
        );
        assert!(got.describe("eth4", 64).contains("SMALLER than before"));
    }

    #[test]
    fn a_failed_write_is_a_failure_even_if_the_table_moved() {
        let mut port = FakePort::new(16);
        port.set_errors = true;
        port.pool = 32;
        let got = ensure(&port, "eth4", 64);
        assert!(
            matches!(&got, Outcome::Failed { why } if why.contains("mailbox timeout") && why.contains("32")),
            "{got:?}"
        );
    }

    #[test]
    fn feasibility_plans_at_the_requested_size_only_where_attach_could_get_it() {
        let port = FakePort::new(16);
        let (t, predicted) = predicted_table(&port, "eth4", Some(64)).unwrap();
        assert_eq!((t.size, predicted), (64, true));
        assert!(port.writes.borrow().is_empty(), "a probe writes nothing");

        let (t, predicted) = predicted_table(&port, "eth4", None).unwrap();
        assert_eq!((t.size, predicted), (16, false));

        let mut busy = FakePort::new(16);
        busy.rules = 2;
        let (t, predicted) = predicted_table(&busy, "eth4", Some(64)).unwrap();
        assert_eq!((t.size, predicted), (16, false), "rules pin the table");

        let mut fixed = FakePort::new(16);
        fixed.adjustable = false;
        let (t, _) = predicted_table(&fixed, "eth4", Some(64)).unwrap();
        assert_eq!(t.size, 16);
    }

    // ----- wire format -----

    #[test]
    fn attributes_are_padded_to_four_bytes() {
        let mut b = Vec::new();
        put_attr(&mut b, 83, &[2]);
        assert_eq!(b.len(), 8, "4 header + 1 payload, padded");
        assert_eq!(
            u16::from_ne_bytes([b[0], b[1]]),
            5,
            "nla_len excludes padding"
        );
        put_str(&mut b, 1, "pci");
        assert_eq!(b.len(), 16, "\"pci\\0\" is exactly 4");
        assert_eq!(attrs(&b), vec![(83, &[2u8][..]), (1, &b"pci\0"[..])]);
    }

    #[test]
    fn a_param_set_carries_name_type_value_and_runtime_cmode() {
        let body = param_set_attrs("pci", "0002:04:00.0", PARAM, 64);
        let got: Vec<(u16, Vec<u8>)> = attrs(&body)
            .into_iter()
            .map(|(t, p)| (t, p.to_vec()))
            .collect();
        assert_eq!(
            got,
            vec![
                (abi::DEVLINK_ATTR_BUS_NAME, b"pci\0".to_vec()),
                (abi::DEVLINK_ATTR_DEV_NAME, b"0002:04:00.0\0".to_vec()),
                (abi::DEVLINK_ATTR_PARAM_NAME, b"mcam_count\0".to_vec()),
                (
                    abi::DEVLINK_ATTR_PARAM_TYPE,
                    vec![abi::DEVLINK_PARAM_TYPE_U16]
                ),
                (
                    abi::DEVLINK_ATTR_PARAM_VALUE_DATA,
                    64u16.to_ne_bytes().to_vec()
                ),
                (
                    abi::DEVLINK_ATTR_PARAM_VALUE_CMODE,
                    vec![abi::DEVLINK_PARAM_CMODE_RUNTIME]
                ),
            ]
        );
        let msg = genl_message(
            0x1a,
            abi::NLM_F_REQUEST | abi::NLM_F_ACK,
            3,
            abi::DEVLINK_CMD_PARAM_SET,
            1,
            &body,
        );
        assert_eq!(
            u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize,
            msg.len()
        );
        assert_eq!(
            (msg[16], msg[17]),
            (abi::DEVLINK_CMD_PARAM_SET, 1),
            "genl cmd + version"
        );
    }

    /// A reply shaped like the kernel's `devlink_nl_param_fill`, built
    /// with the same encoders — plus a second, non-runtime value that
    /// must be skipped.
    fn param_get_reply(seq: u32, value: u16) -> Vec<u8> {
        let value_attr = |cmode: u8, v: u16| {
            let mut f = Vec::new();
            put_attr(&mut f, abi::DEVLINK_ATTR_PARAM_VALUE_CMODE, &[cmode]);
            put_attr(&mut f, abi::DEVLINK_ATTR_PARAM_VALUE_DATA, &v.to_ne_bytes());
            let mut out = Vec::new();
            put_attr(
                &mut out,
                abi::DEVLINK_ATTR_PARAM_VALUE | abi::NLA_F_NESTED,
                &f,
            );
            out
        };
        let mut list = value_attr(2, 999); // permanent cmode — not ours
        list.extend(value_attr(abi::DEVLINK_PARAM_CMODE_RUNTIME, value));
        let mut param = Vec::new();
        put_str(&mut param, abi::DEVLINK_ATTR_PARAM_NAME, PARAM);
        put_attr(
            &mut param,
            abi::DEVLINK_ATTR_PARAM_TYPE,
            &[abi::DEVLINK_PARAM_TYPE_U16],
        );
        put_attr(
            &mut param,
            abi::DEVLINK_ATTR_PARAM_VALUES_LIST | abi::NLA_F_NESTED,
            &list,
        );
        let mut top = Vec::new();
        put_str(&mut top, abi::DEVLINK_ATTR_BUS_NAME, "pci");
        put_str(&mut top, abi::DEVLINK_ATTR_DEV_NAME, "0002:04:00.0");
        put_attr(
            &mut top,
            abi::DEVLINK_ATTR_PARAM | abi::NLA_F_NESTED,
            &param,
        );
        let mut data = genl_message(0x1a, 0, seq, abi::DEVLINK_CMD_PARAM_GET, 1, &top);
        // …then the ACK the request asked for.
        let mut ack = Vec::new();
        ack.extend_from_slice(&36u32.to_ne_bytes());
        ack.extend_from_slice(&abi::NLMSG_ERROR.to_ne_bytes());
        ack.extend_from_slice(&0u16.to_ne_bytes());
        ack.extend_from_slice(&seq.to_ne_bytes());
        ack.extend_from_slice(&0u32.to_ne_bytes());
        ack.extend_from_slice(&0i32.to_ne_bytes());
        ack.extend_from_slice(&[0u8; 16]); // the echoed request header
        data.extend(ack);
        data
    }

    #[test]
    fn a_param_get_reply_yields_the_runtime_value() {
        let mut reply = Reply::default();
        absorb(&mut reply, &param_get_reply(2, 256), 2);
        assert_eq!(reply.status, Some(0));
        assert_eq!(runtime_u16(&reply), Some(256));
    }

    #[test]
    fn messages_for_another_request_are_ignored() {
        let mut reply = Reply::default();
        absorb(&mut reply, &param_get_reply(7, 256), 2);
        assert_eq!(reply, Reply::default());
    }

    #[test]
    fn an_error_reply_carries_the_negative_errno() {
        let mut err = Vec::new();
        err.extend_from_slice(&36u32.to_ne_bytes());
        err.extend_from_slice(&abi::NLMSG_ERROR.to_ne_bytes());
        err.extend_from_slice(&0u16.to_ne_bytes());
        err.extend_from_slice(&3u32.to_ne_bytes());
        err.extend_from_slice(&0u32.to_ne_bytes());
        err.extend_from_slice(&(-libc::EINVAL).to_ne_bytes());
        err.extend_from_slice(&[0u8; 16]);
        let mut reply = Reply::default();
        absorb(&mut reply, &err, 3);
        assert_eq!(reply.status, Some(-libc::EINVAL));
        assert!(errno_text("x", -libc::EINVAL).contains("refuses while any ntuple rule"));
    }

    #[test]
    fn a_family_reply_yields_the_id() {
        let mut a = Vec::new();
        put_str(&mut a, abi::CTRL_ATTR_FAMILY_NAME, abi::DEVLINK_GENL_NAME);
        put_attr(&mut a, abi::CTRL_ATTR_FAMILY_ID, &0x1au16.to_ne_bytes());
        let msg = genl_message(abi::GENL_ID_CTRL, 0, 1, 1, 2, &a);
        let mut reply = Reply::default();
        absorb(&mut reply, &msg, 1);
        assert_eq!(family_id(&reply), Some(0x1a));
    }
}
