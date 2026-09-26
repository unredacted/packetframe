//! NIC interrupt coalescing over `SIOCETHTOOL`
//! (`ETHTOOL_GCOALESCE` / `ETHTOOL_SCOALESCE`).
//!
//! Two consumers: the `iface.<name>.coalesce` feasibility probe reads
//! through [`CoalesceIo::get`], and fast-path's `coalesce` directive
//! reads, merges, writes and reads back at attach (and reverses it at
//! detach). The ioctl sits behind [`CoalesceIo`] so the merge and
//! restore logic is testable on hosts with no ethtool at all; the
//! pure pieces ([`CoalesceSpec`] and the struct layout) carry no
//! platform gate.

use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};

/// `ETHTOOL_GCOALESCE` (uapi `linux/ethtool.h`).
pub const ETHTOOL_GCOALESCE: u32 = 0x0000_000e;
/// `ETHTOOL_SCOALESCE`.
pub const ETHTOOL_SCOALESCE: u32 = 0x0000_000f;

/// uapi `struct ethtool_coalesce`: `cmd` followed by 22 `__u32`
/// parameters, 92 bytes, no padding. The layout is pinned by a unit
/// test; the kernel copies exactly `sizeof(struct ethtool_coalesce)`
/// in both directions, so a short struct here is a kernel write past
/// memory we own.
///
/// `ETHTOOL_SCOALESCE` takes the WHOLE struct, so every write is
/// get → modify → set: fields the caller does not name travel back
/// exactly as the driver reported them (what `ethtool -C` does too).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EthtoolCoalesce {
    pub cmd: u32,
    pub rx_coalesce_usecs: u32,
    pub rx_max_coalesced_frames: u32,
    pub rx_coalesce_usecs_irq: u32,
    pub rx_max_coalesced_frames_irq: u32,
    pub tx_coalesce_usecs: u32,
    pub tx_max_coalesced_frames: u32,
    pub tx_coalesce_usecs_irq: u32,
    pub tx_max_coalesced_frames_irq: u32,
    pub stats_block_coalesce_usecs: u32,
    /// Non-zero means the driver varies the RX settings by packet
    /// rate, so the resting values do not describe behavior under
    /// forwarding load (a resting 50 can become 1 at rate).
    pub use_adaptive_rx_coalesce: u32,
    pub use_adaptive_tx_coalesce: u32,
    pub pkt_rate_low: u32,
    pub rx_coalesce_usecs_low: u32,
    pub rx_max_coalesced_frames_low: u32,
    pub tx_coalesce_usecs_low: u32,
    pub tx_max_coalesced_frames_low: u32,
    pub pkt_rate_high: u32,
    pub rx_coalesce_usecs_high: u32,
    pub rx_max_coalesced_frames_high: u32,
    pub tx_coalesce_usecs_high: u32,
    pub tx_max_coalesced_frames_high: u32,
    pub rate_sample_interval: u32,
}

/// The four parameters PacketFrame manages. Everything else in
/// [`EthtoolCoalesce`] is carried through untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalesceField {
    RxUsecs,
    RxFrames,
    TxUsecs,
    TxFrames,
}

impl CoalesceField {
    pub const ALL: [CoalesceField; 4] = [
        CoalesceField::RxUsecs,
        CoalesceField::RxFrames,
        CoalesceField::TxUsecs,
        CoalesceField::TxFrames,
    ];

    /// The `ethtool -C` / config keyword.
    pub fn keyword(self) -> &'static str {
        match self {
            CoalesceField::RxUsecs => "rx-usecs",
            CoalesceField::RxFrames => "rx-frames",
            CoalesceField::TxUsecs => "tx-usecs",
            CoalesceField::TxFrames => "tx-frames",
        }
    }

    pub fn from_keyword(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.keyword() == s)
    }

    fn slot(self, raw: &mut EthtoolCoalesce) -> &mut u32 {
        match self {
            CoalesceField::RxUsecs => &mut raw.rx_coalesce_usecs,
            CoalesceField::RxFrames => &mut raw.rx_max_coalesced_frames,
            CoalesceField::TxUsecs => &mut raw.tx_coalesce_usecs,
            CoalesceField::TxFrames => &mut raw.tx_max_coalesced_frames,
        }
    }

    pub fn read(self, raw: &EthtoolCoalesce) -> u32 {
        match self {
            CoalesceField::RxUsecs => raw.rx_coalesce_usecs,
            CoalesceField::RxFrames => raw.rx_max_coalesced_frames,
            CoalesceField::TxUsecs => raw.tx_coalesce_usecs,
            CoalesceField::TxFrames => raw.tx_max_coalesced_frames,
        }
    }
}

/// A partial coalescing setting: `None` means "leave this parameter
/// as the driver has it". The same shape serves three roles — what
/// the config asks for, what the NIC held before PacketFrame touched
/// it (the restore record), and what the NIC reported after — so a
/// restore is just another merge.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalesceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_usecs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_frames: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_usecs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_frames: Option<u32>,
}

impl CoalesceSpec {
    pub fn get(&self, f: CoalesceField) -> Option<u32> {
        match f {
            CoalesceField::RxUsecs => self.rx_usecs,
            CoalesceField::RxFrames => self.rx_frames,
            CoalesceField::TxUsecs => self.tx_usecs,
            CoalesceField::TxFrames => self.tx_frames,
        }
    }

    pub fn set(&mut self, f: CoalesceField, v: Option<u32>) {
        match f {
            CoalesceField::RxUsecs => self.rx_usecs = v,
            CoalesceField::RxFrames => self.rx_frames = v,
            CoalesceField::TxUsecs => self.tx_usecs = v,
            CoalesceField::TxFrames => self.tx_frames = v,
        }
    }

    pub fn is_empty(&self) -> bool {
        CoalesceField::ALL.iter().all(|f| self.get(*f).is_none())
    }

    /// The fields this spec names, in declaration order.
    pub fn fields(&self) -> impl Iterator<Item = CoalesceField> + '_ {
        CoalesceField::ALL
            .into_iter()
            .filter(|f| self.get(*f).is_some())
    }

    /// Write every named field into `raw`; unnamed fields keep the
    /// driver's value.
    pub fn merge_into(&self, raw: &mut EthtoolCoalesce) {
        for f in self.fields() {
            *f.slot(raw) = self.get(f).expect("fields() yields named fields only");
        }
    }

    /// `raw`'s values for exactly the fields this spec names.
    pub fn snapshot(&self, raw: &EthtoolCoalesce) -> CoalesceSpec {
        let mut out = CoalesceSpec::default();
        for f in self.fields() {
            out.set(f, Some(f.read(raw)));
        }
        out
    }

    /// Field-wise: `self`'s value where named, else `other`'s.
    pub fn or(&self, other: &CoalesceSpec) -> CoalesceSpec {
        let mut out = *other;
        for f in self.fields() {
            out.set(f, self.get(f));
        }
        out
    }

    /// `self` with every field `other` names cleared.
    pub fn without(&self, other: &CoalesceSpec) -> CoalesceSpec {
        let mut out = *self;
        for f in other.fields() {
            out.set(f, None);
        }
        out
    }

    /// Named fields `raw` does not hold, as `(field, wanted, got)`.
    /// Non-empty after a confirmed write means the driver clamped or
    /// coupled a value (some drivers bound the timer, or share one
    /// completion queue between an rx/tx pair and pick one value).
    pub fn mismatches(&self, raw: &EthtoolCoalesce) -> Vec<(CoalesceField, u32, u32)> {
        self.fields()
            .filter_map(|f| {
                let want = self.get(f).expect("named");
                let got = f.read(raw);
                (want != got).then_some((f, want, got))
            })
            .collect()
    }

    /// What a restore may write back. For each field in `prior`:
    /// restored when `applied` has no confirmed value for it (the
    /// write was never read back, so what the NIC holds is unknown),
    /// or when the NIC still holds the confirmed value. A field that
    /// has moved since is someone else's change and is left alone —
    /// returned in the second element so the caller can say so.
    pub fn restore_plan(
        prior: &CoalesceSpec,
        applied: &CoalesceSpec,
        current: &EthtoolCoalesce,
    ) -> (CoalesceSpec, Vec<CoalesceField>) {
        let mut plan = CoalesceSpec::default();
        let mut moved = Vec::new();
        for f in prior.fields() {
            match applied.get(f) {
                Some(ours) if f.read(current) != ours => moved.push(f),
                _ => plan.set(f, prior.get(f)),
            }
        }
        (plan, moved)
    }
}

impl fmt::Display for CoalesceSpec {
    /// `rx-usecs 50 rx-frames 32`, the config / `ethtool -C` spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for field in self.fields() {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            write!(f, "{} {}", field.keyword(), self.get(field).expect("named"))?;
        }
        if first {
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

/// The ioctl seam. [`SiocEthtool`] is the real one; tests substitute
/// a fake that can refuse, clamp, or record.
pub trait CoalesceIo {
    fn get(&self, iface: &str) -> io::Result<EthtoolCoalesce>;
    fn set(&self, iface: &str, value: &EthtoolCoalesce) -> io::Result<()>;
}

/// `SIOCETHTOOL` on an `AF_INET` datagram socket. Reads need no
/// privilege; writes need `CAP_NET_ADMIN`. Non-Linux targets answer
/// `ENOSYS`, like the rest of the repo's platform stubs.
#[derive(Debug, Clone, Copy, Default)]
pub struct SiocEthtool;

impl CoalesceIo for SiocEthtool {
    fn get(&self, iface: &str) -> io::Result<EthtoolCoalesce> {
        let mut value = EthtoolCoalesce {
            cmd: ETHTOOL_GCOALESCE,
            ..Default::default()
        };
        siocethtool(iface, &mut value)?;
        Ok(value)
    }

    fn set(&self, iface: &str, value: &EthtoolCoalesce) -> io::Result<()> {
        let mut value = EthtoolCoalesce {
            cmd: ETHTOOL_SCOALESCE,
            ..*value
        };
        siocethtool(iface, &mut value)
    }
}

#[cfg(target_os = "linux")]
fn siocethtool(iface: &str, value: &mut EthtoolCoalesce) -> io::Result<()> {
    // Width-neutral: libc::ioctl's request parameter is `c_ulong` on
    // glibc but `c_int` on musl, so the constant is a plain u32 and
    // the call site casts with `as _` (same pattern as the GRO probe).
    const SIOCETHTOOL: u32 = 0x8946;

    let name_bytes = iface.as_bytes();
    // SAFETY: ifreq is plain old data; all-zero is a valid value.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if name_bytes.len() >= ifr.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name `{iface}` exceeds IFNAMSIZ"),
        ));
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
        *dst = *src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_data = value as *mut EthtoolCoalesce as *mut libc::c_char;

    // SAFETY: plain socket(2); the fd is closed below on every path.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `ifr` points at `value`, a live repr(C) struct of the
    // exact size the kernel copies for these two commands.
    #[allow(clippy::unnecessary_cast)]
    let r = unsafe { libc::ioctl(sock, SIOCETHTOOL as _, &mut ifr) };
    let err = io::Error::last_os_error();
    // SAFETY: `sock` is the fd opened above.
    unsafe { libc::close(sock) };
    if r != 0 {
        return Err(err);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn siocethtool(_iface: &str, _value: &mut EthtoolCoalesce) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// The uapi layout, field by field for the ones PacketFrame
    /// reads or writes, and the total the kernel copies.
    #[test]
    fn struct_matches_uapi_layout() {
        assert_eq!(size_of::<EthtoolCoalesce>(), 92);
        assert_eq!(offset_of!(EthtoolCoalesce, cmd), 0);
        assert_eq!(offset_of!(EthtoolCoalesce, rx_coalesce_usecs), 4);
        assert_eq!(offset_of!(EthtoolCoalesce, rx_max_coalesced_frames), 8);
        assert_eq!(offset_of!(EthtoolCoalesce, tx_coalesce_usecs), 20);
        assert_eq!(offset_of!(EthtoolCoalesce, tx_max_coalesced_frames), 24);
        assert_eq!(offset_of!(EthtoolCoalesce, use_adaptive_rx_coalesce), 40);
        assert_eq!(offset_of!(EthtoolCoalesce, rate_sample_interval), 88);
    }

    #[test]
    fn command_numbers_match_uapi() {
        assert_eq!(ETHTOOL_GCOALESCE, 14);
        assert_eq!(ETHTOOL_SCOALESCE, 15);
    }

    fn stock() -> EthtoolCoalesce {
        EthtoolCoalesce {
            rx_coalesce_usecs: 1,
            rx_max_coalesced_frames: 10,
            tx_coalesce_usecs: 1,
            tx_max_coalesced_frames: 10,
            rx_coalesce_usecs_irq: 7,
            pkt_rate_high: 99,
            ..Default::default()
        }
    }

    #[test]
    fn merge_touches_only_named_fields() {
        let spec = CoalesceSpec {
            rx_usecs: Some(50),
            tx_frames: Some(32),
            ..Default::default()
        };
        let mut raw = stock();
        spec.merge_into(&mut raw);
        assert_eq!(raw.rx_coalesce_usecs, 50);
        assert_eq!(raw.tx_max_coalesced_frames, 32);
        // Unnamed managed fields and every unmanaged field ride through.
        assert_eq!(raw.rx_max_coalesced_frames, 10);
        assert_eq!(raw.tx_coalesce_usecs, 1);
        assert_eq!(raw.rx_coalesce_usecs_irq, 7);
        assert_eq!(raw.pkt_rate_high, 99);
    }

    #[test]
    fn snapshot_captures_exactly_the_named_fields() {
        let spec = CoalesceSpec {
            rx_usecs: Some(50),
            rx_frames: Some(32),
            ..Default::default()
        };
        let prior = spec.snapshot(&stock());
        assert_eq!(
            prior,
            CoalesceSpec {
                rx_usecs: Some(1),
                rx_frames: Some(10),
                ..Default::default()
            }
        );
        // The prior restores the NIC to where it was.
        let mut raw = stock();
        spec.merge_into(&mut raw);
        prior.merge_into(&mut raw);
        assert_eq!(raw, stock());
    }

    #[test]
    fn or_and_without_are_field_wise() {
        let a = CoalesceSpec {
            rx_usecs: Some(1),
            ..Default::default()
        };
        let b = CoalesceSpec {
            rx_usecs: Some(9),
            tx_usecs: Some(2),
            ..Default::default()
        };
        assert_eq!(
            a.or(&b),
            CoalesceSpec {
                rx_usecs: Some(1),
                tx_usecs: Some(2),
                ..Default::default()
            }
        );
        assert_eq!(
            b.without(&a),
            CoalesceSpec {
                tx_usecs: Some(2),
                ..Default::default()
            }
        );
    }

    #[test]
    fn mismatches_report_clamped_values() {
        let spec = CoalesceSpec {
            rx_usecs: Some(50),
            rx_frames: Some(32),
            ..Default::default()
        };
        let mut raw = stock();
        spec.merge_into(&mut raw);
        assert!(spec.mismatches(&raw).is_empty());
        raw.rx_coalesce_usecs = 25; // a driver-side clamp
        assert_eq!(
            spec.mismatches(&raw),
            vec![(CoalesceField::RxUsecs, 50, 25)]
        );
    }

    #[test]
    fn restore_plan_leaves_fields_someone_else_moved() {
        let prior = CoalesceSpec {
            rx_usecs: Some(1),
            rx_frames: Some(10),
            tx_usecs: Some(1),
            ..Default::default()
        };
        // rx-usecs confirmed at 50; rx-frames never confirmed (the
        // write was interrupted); tx-usecs confirmed at 50.
        let applied = CoalesceSpec {
            rx_usecs: Some(50),
            tx_usecs: Some(50),
            ..Default::default()
        };
        let current = EthtoolCoalesce {
            rx_coalesce_usecs: 50,      // still ours
            rx_max_coalesced_frames: 3, // unknown provenance: restore
            tx_coalesce_usecs: 80,      // moved by an operator: leave
            ..Default::default()
        };
        let (plan, moved) = CoalesceSpec::restore_plan(&prior, &applied, &current);
        assert_eq!(
            plan,
            CoalesceSpec {
                rx_usecs: Some(1),
                rx_frames: Some(10),
                ..Default::default()
            }
        );
        assert_eq!(moved, vec![CoalesceField::TxUsecs]);
    }

    #[test]
    fn display_uses_config_spelling() {
        let spec = CoalesceSpec {
            rx_usecs: Some(50),
            rx_frames: Some(32),
            tx_usecs: Some(50),
            tx_frames: Some(32),
        };
        assert_eq!(
            spec.to_string(),
            "rx-usecs 50 rx-frames 32 tx-usecs 50 tx-frames 32"
        );
        assert_eq!(CoalesceSpec::default().to_string(), "(none)");
    }

    #[test]
    fn keywords_round_trip() {
        for f in CoalesceField::ALL {
            assert_eq!(CoalesceField::from_keyword(f.keyword()), Some(f));
        }
        assert_eq!(CoalesceField::from_keyword("adaptive-rx"), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_stub_is_enosys() {
        let e = SiocEthtool.get("eth0").unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOSYS));
    }
}
