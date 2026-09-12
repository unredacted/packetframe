//! The learned table, the kernel-neighbour mirror, the install
//! decision and the admission filter. All portable and pure: the
//! Linux engine feeds them observations and acts on their verdicts.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use crate::frame::Source;

/// One learned `(ip → mac)` fact and when we last heard it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedEntry {
    pub mac: [u8; 6],
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    /// Monotonic twin of `last_seen`, used for eviction order and
    /// the install holddown so wall-clock steps cannot reorder them.
    pub last_seen_mono: Instant,
    pub source: Source,
    /// When we last asked the kernel to install this pair; drives the
    /// STALE-override holddown in [`install_decision`].
    pub last_install: Option<Instant>,
}

/// What [`LearnedTable::observe`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observe {
    New,
    Refreshed,
    MacChanged { old: [u8; 6] },
}

/// Per-bridge learned table with a hard cap and least-recently-seen
/// eviction. Eviction is a linear scan: it is rare (only when the cap
/// is hit) and the cap is thousands, not millions.
#[derive(Debug, Clone)]
pub struct LearnedTable {
    cap: usize,
    entries: HashMap<IpAddr, LearnedEntry>,
}

impl LearnedTable {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&LearnedEntry> {
        self.entries.get(ip)
    }

    pub fn get_mut(&mut self, ip: &IpAddr) -> Option<&mut LearnedEntry> {
        self.entries.get_mut(ip)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpAddr, &LearnedEntry)> {
        self.entries.iter()
    }

    pub fn remove(&mut self, ip: &IpAddr) -> Option<LearnedEntry> {
        self.entries.remove(ip)
    }

    /// Record a sighting. Returns what changed and, when the cap forced
    /// it, the address that was evicted to make room.
    pub fn observe(
        &mut self,
        ip: IpAddr,
        mac: [u8; 6],
        source: Source,
        now: SystemTime,
        now_mono: Instant,
    ) -> (Observe, Option<IpAddr>) {
        if let Some(e) = self.entries.get_mut(&ip) {
            let outcome = if e.mac == mac {
                Observe::Refreshed
            } else {
                let old = e.mac;
                e.mac = mac;
                // A new MAC is a new fact; the holddown protected the
                // old one, not this one.
                e.last_install = None;
                Observe::MacChanged { old }
            };
            e.last_seen = now;
            e.last_seen_mono = now_mono;
            e.source = source;
            return (outcome, None);
        }
        let evicted = if self.entries.len() >= self.cap {
            self.evict_lru()
        } else {
            None
        };
        self.entries.insert(
            ip,
            LearnedEntry {
                mac,
                first_seen: now,
                last_seen: now,
                last_seen_mono: now_mono,
                source,
                last_install: None,
            },
        );
        (Observe::New, evicted)
    }

    /// Insert an entry restored from disk. Existing entries win (they
    /// are fresher by construction). Returns the evicted address, if
    /// the cap forced one.
    pub fn insert_restored(&mut self, ip: IpAddr, entry: LearnedEntry) -> Option<IpAddr> {
        if self.entries.contains_key(&ip) {
            return None;
        }
        let evicted = if self.entries.len() >= self.cap {
            self.evict_lru()
        } else {
            None
        };
        self.entries.insert(ip, entry);
        evicted
    }

    /// Change the cap; a shrink evicts least-recently-seen entries and
    /// returns them so the caller can count them.
    pub fn set_cap(&mut self, cap: usize) -> Vec<IpAddr> {
        self.cap = cap.max(1);
        let mut evicted = Vec::new();
        while self.entries.len() > self.cap {
            match self.evict_lru() {
                Some(ip) => evicted.push(ip),
                None => break,
            }
        }
        evicted
    }

    /// Drop entries whose `last_seen` is older than `max_age` relative
    /// to `now`; returns them.
    pub fn expire(&mut self, now: SystemTime, max_age: Duration) -> Vec<IpAddr> {
        let cutoff = now.checked_sub(max_age);
        let Some(cutoff) = cutoff else {
            return Vec::new();
        };
        let old: Vec<IpAddr> = self
            .entries
            .iter()
            .filter(|(_, e)| e.last_seen < cutoff)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in &old {
            self.entries.remove(ip);
        }
        old
    }

    fn evict_lru(&mut self) -> Option<IpAddr> {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_seen_mono)
            .map(|(ip, _)| *ip)?;
        self.entries.remove(&victim);
        Some(victim)
    }
}

/// Kernel NUD state, portable. The Linux side converts the netlink
/// enum to the raw `NUD_*` bits and back through [`NudState::from_raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NudState {
    None,
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Noarp,
    Permanent,
    Other(u16),
}

impl NudState {
    pub fn from_raw(raw: u16) -> Self {
        match raw {
            0x00 => Self::None,
            0x01 => Self::Incomplete,
            0x02 => Self::Reachable,
            0x04 => Self::Stale,
            0x08 => Self::Delay,
            0x10 => Self::Probe,
            0x20 => Self::Failed,
            0x40 => Self::Noarp,
            0x80 => Self::Permanent,
            other => Self::Other(other),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Incomplete => "incomplete",
            Self::Reachable => "reachable",
            Self::Stale => "stale",
            Self::Delay => "delay",
            Self::Probe => "probe",
            Self::Failed => "failed",
            Self::Noarp => "noarp",
            Self::Permanent => "permanent",
            Self::Other(_) => "other",
        }
    }

    /// The kernel got a unicast reply from the MAC it holds (or is in
    /// the middle of confirming one it recently held). A snooped frame
    /// never overrides these.
    pub fn is_confirmed(self) -> bool {
        matches!(self, Self::Reachable | Self::Delay | Self::Probe)
    }

    /// A state in which a held MAC is usable for forwarding.
    pub fn is_valid(self) -> bool {
        matches!(
            self,
            Self::Reachable
                | Self::Stale
                | Self::Delay
                | Self::Probe
                | Self::Permanent
                | Self::Noarp
        )
    }
}

/// What the kernel holds for one `(ifindex, ip)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorEntry {
    pub state: NudState,
    pub mac: Option<[u8; 6]>,
}

impl MirrorEntry {
    /// The entry resolves: a MAC in a valid state.
    pub fn resolves(&self) -> bool {
        self.mac.is_some() && self.state.is_valid()
    }
}

/// Mirror of the kernel neighbour table for the tracked bridges only.
#[derive(Debug, Clone, Default)]
pub struct KernelMirror {
    entries: HashMap<(u32, IpAddr), MirrorEntry>,
}

impl KernelMirror {
    pub fn get(&self, ifindex: u32, ip: &IpAddr) -> Option<&MirrorEntry> {
        self.entries.get(&(ifindex, *ip))
    }

    pub fn upsert(&mut self, ifindex: u32, ip: IpAddr, entry: MirrorEntry) -> Option<MirrorEntry> {
        self.entries.insert((ifindex, ip), entry)
    }

    pub fn remove(&mut self, ifindex: u32, ip: &IpAddr) -> Option<MirrorEntry> {
        self.entries.remove(&(ifindex, *ip))
    }

    /// Forget everything on a device that went away.
    pub fn purge_ifindex(&mut self, ifindex: u32) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(i, _), _| *i != ifindex);
        before - self.entries.len()
    }

    pub fn iter_ifindex(&self, ifindex: u32) -> impl Iterator<Item = (&IpAddr, &MirrorEntry)> {
        self.entries
            .iter()
            .filter(move |((i, _), _)| *i == ifindex)
            .map(|((_, ip), e)| (ip, e))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallReason {
    /// No kernel entry at all.
    Absent,
    /// Incomplete / Failed / None: the kernel holds nothing usable.
    Unusable,
    /// A STALE entry holding a different (or no) MAC.
    MacDiffers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The kernel already holds this MAC in a valid state; an ADMIN
    /// write of STALE would downgrade a confirmed entry.
    SameMac,
    /// Operator statics are never touched, and PERMANENT is never
    /// written.
    Permanent,
    /// Kernel-managed (multicast, point-to-point).
    Noarp,
    /// A state this code does not know; refuse to act on it.
    UnknownState,
    /// A STALE override was requested too recently for this entry.
    Holddown,
    /// The kernel has *confirmed* a different MAC by unicast reply. A
    /// snooped frame claiming otherwise is more likely a second router
    /// leaking on that participant's port than a real move; NUD will
    /// move the entry to FAILED if the held MAC stops answering, and
    /// FAILED is repaired.
    MacConflict,
}

impl SkipReason {
    pub const COUNT: usize = 6;
    pub const LABELS: [&'static str; Self::COUNT] = [
        "same_mac",
        "permanent",
        "noarp",
        "unknown_state",
        "holddown",
        "mac_conflict",
    ];

    pub fn index(self) -> usize {
        match self {
            Self::SameMac => 0,
            Self::Permanent => 1,
            Self::Noarp => 2,
            Self::UnknownState => 3,
            Self::Holddown => 4,
            Self::MacConflict => 5,
        }
    }

    pub fn label(self) -> &'static str {
        Self::LABELS[self.index()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Install(InstallReason),
    Skip(SkipReason),
}

/// Minimum spacing between two STALE overrides of the same entry, so
/// two routers leaking the same address cannot flap it.
pub const DEFAULT_HOLDDOWN: Duration = Duration::from_secs(30);

/// The R4 rule as a truth table. `kernel` is the mirror's view of the
/// entry (None = absent), `learned` the MAC just heard, `last_install`
/// when we last wrote this entry.
pub fn install_decision(
    kernel: Option<&MirrorEntry>,
    learned: [u8; 6],
    last_install: Option<Instant>,
    now: Instant,
    holddown: Duration,
) -> Decision {
    let Some(k) = kernel else {
        return Decision::Install(InstallReason::Absent);
    };
    match k.state {
        NudState::None | NudState::Incomplete | NudState::Failed => {
            Decision::Install(InstallReason::Unusable)
        }
        NudState::Permanent => Decision::Skip(SkipReason::Permanent),
        NudState::Noarp => Decision::Skip(SkipReason::Noarp),
        NudState::Reachable | NudState::Delay | NudState::Probe => {
            if k.mac == Some(learned) {
                Decision::Skip(SkipReason::SameMac)
            } else {
                Decision::Skip(SkipReason::MacConflict)
            }
        }
        NudState::Stale => {
            if k.mac == Some(learned) {
                Decision::Skip(SkipReason::SameMac)
            } else if last_install.is_some_and(|t| now.duration_since(t) < holddown) {
                Decision::Skip(SkipReason::Holddown)
            } else {
                Decision::Install(InstallReason::MacDiffers)
            }
        }
        NudState::Other(_) => Decision::Skip(SkipReason::UnknownState),
    }
}

/// Why a learned pair was not admitted to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterReject {
    OutsidePrefix,
    OwnAddress,
    OwnMac,
    DeniedMac,
}

impl FilterReject {
    pub const COUNT: usize = 4;
    pub const LABELS: [&'static str; Self::COUNT] =
        ["outside_prefix", "own_address", "own_mac", "denied_mac"];

    pub fn index(self) -> usize {
        match self {
            Self::OutsidePrefix => 0,
            Self::OwnAddress => 1,
            Self::OwnMac => 2,
            Self::DeniedMac => 3,
        }
    }

    pub fn label(self) -> &'static str {
        Self::LABELS[self.index()]
    }
}

/// The R3 admission filter. Own address and own MAC first (a VRRP
/// address moving between routers must never be learned as a peer),
/// then the deny list, then the prefix allowlist.
pub fn admit(
    ip: IpAddr,
    mac: [u8; 6],
    prefixes: &[ipnet::IpNet],
    own_addrs: &HashSet<IpAddr>,
    own_mac: Option<[u8; 6]>,
    deny_macs: &[[u8; 6]],
) -> Result<(), FilterReject> {
    if own_addrs.contains(&ip) {
        return Err(FilterReject::OwnAddress);
    }
    if own_mac == Some(mac) {
        return Err(FilterReject::OwnMac);
    }
    if deny_macs.contains(&mac) {
        return Err(FilterReject::DeniedMac);
    }
    if !prefixes.iter().any(|p| p.contains(&ip)) {
        return Err(FilterReject::OutsidePrefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }
    fn m(state: NudState, mac: Option<[u8; 6]>) -> MirrorEntry {
        MirrorEntry { state, mac }
    }

    #[test]
    fn install_decision_truth_table() {
        let now = Instant::now();
        let h = DEFAULT_HOLDDOWN;
        use Decision::*;
        use InstallReason as I;
        use SkipReason as S;
        assert_eq!(install_decision(None, A, None, now, h), Install(I::Absent));
        for st in [NudState::None, NudState::Incomplete, NudState::Failed] {
            assert_eq!(
                install_decision(Some(&m(st, Some(B))), A, None, now, h),
                Install(I::Unusable),
                "{st:?}"
            );
            assert_eq!(
                install_decision(Some(&m(st, None)), A, None, now, h),
                Install(I::Unusable)
            );
        }
        assert_eq!(
            install_decision(Some(&m(NudState::Permanent, Some(B))), A, None, now, h),
            Skip(S::Permanent)
        );
        assert_eq!(
            install_decision(Some(&m(NudState::Noarp, None)), A, None, now, h),
            Skip(S::Noarp)
        );
        for st in [NudState::Reachable, NudState::Delay, NudState::Probe] {
            assert_eq!(
                install_decision(Some(&m(st, Some(A))), A, None, now, h),
                Skip(S::SameMac),
                "{st:?}"
            );
            // Confirmed entries are never overridden, even with no
            // recent install of ours.
            assert_eq!(
                install_decision(Some(&m(st, Some(B))), A, None, now, h),
                Skip(S::MacConflict),
                "{st:?}"
            );
            assert_eq!(
                install_decision(Some(&m(st, None)), A, None, now, h),
                Skip(S::MacConflict),
                "{st:?}"
            );
        }
        assert_eq!(
            install_decision(Some(&m(NudState::Stale, Some(A))), A, None, now, h),
            Skip(S::SameMac)
        );
        assert_eq!(
            install_decision(Some(&m(NudState::Stale, Some(B))), A, None, now, h),
            Install(I::MacDiffers)
        );
        assert_eq!(
            install_decision(Some(&m(NudState::Stale, None)), A, None, now, h),
            Install(I::MacDiffers)
        );
        // Holddown applies only to the STALE override.
        let recent = Some(now - Duration::from_secs(5));
        assert_eq!(
            install_decision(Some(&m(NudState::Stale, Some(B))), A, recent, now, h),
            Skip(S::Holddown)
        );
        let old = Some(now - Duration::from_secs(60));
        assert_eq!(
            install_decision(Some(&m(NudState::Stale, Some(B))), A, old, now, h),
            Install(I::MacDiffers)
        );
        assert_eq!(
            install_decision(Some(&m(NudState::Failed, Some(B))), A, recent, now, h),
            Install(I::Unusable)
        );
        assert_eq!(
            install_decision(Some(&m(NudState::Other(0x3), Some(A))), A, None, now, h),
            Skip(S::UnknownState)
        );
    }

    #[test]
    fn nud_raw_round_trip() {
        for (raw, st) in [
            (0x00, NudState::None),
            (0x01, NudState::Incomplete),
            (0x02, NudState::Reachable),
            (0x04, NudState::Stale),
            (0x08, NudState::Delay),
            (0x10, NudState::Probe),
            (0x20, NudState::Failed),
            (0x40, NudState::Noarp),
            (0x80, NudState::Permanent),
            (0x06, NudState::Other(0x06)),
        ] {
            assert_eq!(NudState::from_raw(raw), st);
        }
        assert!(NudState::Stale.is_valid());
        assert!(!NudState::Failed.is_valid());
        assert!(NudState::Probe.is_confirmed());
        assert!(!NudState::Stale.is_confirmed());
    }

    #[test]
    fn table_observe_new_refresh_change() {
        let mut t = LearnedTable::new(10);
        let now = SystemTime::now();
        let mono = Instant::now();
        let (o, ev) = t.observe(ip(1), A, Source::ArpRequest, now, mono);
        assert_eq!((o, ev), (Observe::New, None));
        let later = now + Duration::from_secs(5);
        let (o, _) = t.observe(ip(1), A, Source::ArpReply, later, mono);
        assert_eq!(o, Observe::Refreshed);
        assert_eq!(t.get(&ip(1)).unwrap().last_seen, later);
        assert_eq!(t.get(&ip(1)).unwrap().first_seen, now);
        t.get_mut(&ip(1)).unwrap().last_install = Some(mono);
        let (o, _) = t.observe(ip(1), B, Source::ArpRequest, later, mono);
        assert_eq!(o, Observe::MacChanged { old: A });
        assert_eq!(t.get(&ip(1)).unwrap().mac, B);
        assert!(
            t.get(&ip(1)).unwrap().last_install.is_none(),
            "a new MAC resets the holddown"
        );
    }

    #[test]
    fn table_evicts_least_recently_seen() {
        let mut t = LearnedTable::new(3);
        let now = SystemTime::now();
        let base = Instant::now();
        for i in 1..=3u8 {
            t.observe(
                ip(i),
                A,
                Source::ArpRequest,
                now,
                base + Duration::from_secs(i as u64),
            );
        }
        // Refresh 1 so 2 is the oldest.
        t.observe(
            ip(1),
            A,
            Source::ArpRequest,
            now,
            base + Duration::from_secs(10),
        );
        let (o, ev) = t.observe(
            ip(4),
            A,
            Source::ArpRequest,
            now,
            base + Duration::from_secs(11),
        );
        assert_eq!(o, Observe::New);
        assert_eq!(ev, Some(ip(2)));
        assert_eq!(t.len(), 3);
        assert!(t.get(&ip(2)).is_none());

        let evicted = t.set_cap(1);
        assert_eq!(t.len(), 1);
        assert_eq!(evicted.len(), 2);
        assert!(t.get(&ip(4)).is_some(), "the newest survives a shrink");
    }

    #[test]
    fn table_expire_drops_old_entries() {
        let mut t = LearnedTable::new(10);
        let now = SystemTime::now();
        let mono = Instant::now();
        t.observe(
            ip(1),
            A,
            Source::ArpRequest,
            now - Duration::from_secs(20 * 86_400),
            mono,
        );
        t.observe(
            ip(2),
            A,
            Source::ArpRequest,
            now - Duration::from_secs(60),
            mono,
        );
        let dropped = t.expire(now, Duration::from_secs(14 * 86_400));
        assert_eq!(dropped, vec![ip(1)]);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn restored_entries_do_not_overwrite_live_ones() {
        let mut t = LearnedTable::new(10);
        let now = SystemTime::now();
        let mono = Instant::now();
        t.observe(ip(1), A, Source::ArpRequest, now, mono);
        let restored = LearnedEntry {
            mac: B,
            first_seen: now,
            last_seen: now,
            last_seen_mono: mono,
            source: Source::ArpReply,
            last_install: None,
        };
        assert_eq!(t.insert_restored(ip(1), restored.clone()), None);
        assert_eq!(t.get(&ip(1)).unwrap().mac, A);
        assert_eq!(t.insert_restored(ip(2), restored), None);
        assert_eq!(t.get(&ip(2)).unwrap().mac, B);
    }

    #[test]
    fn mirror_purge_and_iter() {
        let mut m = KernelMirror::default();
        m.upsert(
            3,
            ip(1),
            MirrorEntry {
                state: NudState::Stale,
                mac: Some(A),
            },
        );
        m.upsert(
            3,
            ip(2),
            MirrorEntry {
                state: NudState::Failed,
                mac: None,
            },
        );
        m.upsert(
            4,
            ip(1),
            MirrorEntry {
                state: NudState::Reachable,
                mac: Some(B),
            },
        );
        assert_eq!(m.iter_ifindex(3).count(), 2);
        assert!(m.get(3, &ip(1)).unwrap().resolves());
        assert!(!m.get(3, &ip(2)).unwrap().resolves());
        assert_eq!(m.purge_ifindex(3), 2);
        assert_eq!(m.len(), 1);
        assert!(m.get(4, &ip(1)).is_some());
    }

    #[test]
    fn admit_filters_in_order() {
        let prefixes: Vec<ipnet::IpNet> = vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8:1::/64".parse().unwrap(),
            "fe80::/10".parse().unwrap(),
        ];
        let own_addrs: HashSet<IpAddr> = [ip(1)].into_iter().collect();
        let deny = [B];
        assert_eq!(
            admit(
                ip(2),
                A,
                &prefixes,
                &own_addrs,
                Some([0x02, 0, 0, 0, 0, 0xee]),
                &deny
            ),
            Ok(())
        );
        assert_eq!(
            admit(ip(1), A, &prefixes, &own_addrs, None, &deny),
            Err(FilterReject::OwnAddress)
        );
        assert_eq!(
            admit(ip(2), A, &prefixes, &own_addrs, Some(A), &deny),
            Err(FilterReject::OwnMac)
        );
        assert_eq!(
            admit(ip(2), B, &prefixes, &own_addrs, None, &deny),
            Err(FilterReject::DeniedMac)
        );
        let outside = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert_eq!(
            admit(outside, A, &prefixes, &own_addrs, None, &deny),
            Err(FilterReject::OutsidePrefix)
        );
        let ll = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(admit(ll, A, &prefixes, &own_addrs, None, &deny), Ok(()));
        let g = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1));
        assert_eq!(
            admit(g, A, &prefixes, &own_addrs, None, &deny),
            Err(FilterReject::OutsidePrefix)
        );
    }
}
