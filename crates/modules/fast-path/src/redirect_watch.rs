//! Keeps the redirect-target maps, and the VLAN resolution they depend
//! on, in step with the kernel's link table for the life of the attach.
//!
//! `REDIRECT_DEVMAP` (XDP) and `TC_REDIRECT_TARGETS` (tc) are the
//! datapath's pre-check that a FIB-resolved egress is a device it may
//! redirect to (SPEC.md §4.4 step 9d). Both were filled once at attach
//! from `/sys/class/net` and again only on SIGHUP. Any Ethernet link
//! that appeared in between — the platform re-creates bridges and VLAN
//! sub-interfaces on every provisioning pass, with new ifindexes — was
//! not a valid target, so every packet the FIB resolved to it took
//! XDP_PASS into the kernel path and counted `pass_not_in_devmap`. On
//! 2026-09-15 that was 5 % of the primary's traffic over the old
//! daemon's life.
//!
//! `VLAN_RESOLVE` is the other half of the same fact: a recreated
//! sub-interface or bridge admitted as a redirect target *without* its
//! translation to physical port + VID would be redirected to the
//! virtual device itself — which is a slower path under generic XDP
//! and a dropped frame under native (no `ndo_xdp_xmit`). So the
//! translation is written first and the target admitted after.
//!
//! This watcher subscribes to `RTNLGRP_LINK` on its own thread. Link
//! events are debounced for a quarter second (provisioning re-creates
//! dozens of links in a burst) into one *topology refresh*: recompute
//! the desired `VLAN_RESOLVE` from the same rule the SIGHUP reconcile
//! uses, apply the diff, set the `VLAN_PRESENT` gate, and only then
//! admit the redirect targets that came up. Deletions leave the
//! redirect maps immediately. One refresh runs right after the
//! subscription is live so nothing slips between the attach-time fill
//! and the first event. Everything is opened from the bpffs pins like
//! the rest of the control plane, and it runs in every forwarding mode:
//! the pre-check is the same under kernel-fib and custom-fib.
//!
//! Membership policy is the one the SIGHUP reconcile already applies:
//! an Ethernet link becomes a target when the kernel reports it oper-up
//! (or `unknown`, which virtual devices report for lack of carrier
//! detection) and stays one until the kernel deletes it. Going
//! oper-down does not remove it — the kernel refuses a redirect to a
//! down device and the frame is counted, which is the conservative
//! failure and identical to what the attach-time fill would have left.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use aya::maps::{xdp::DevMapHash, Array, HashMap as AyaHashMap, Map, MapData};
use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::link::{LinkAttribute, LinkLayerType, LinkMessage, State};
use netlink_packet_route::RouteNetlinkMessage;
use packetframe_common::config::ModuleDirective;
use rtnetlink::{new_multicast_connection, MulticastGroup};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::linux_impl::{
    enumerate_redirect_targets, set_cfg_flag_in, FpCfg, VlanResolve, FP_CFG_FLAG_VLAN_PRESENT,
};
use crate::pin;
use crate::reconcile::{apply_vlan_resolve, desired_vlan_resolve, ifindex_exists};

/// How long after the last link event the topology refresh runs.
/// Long enough to fold a provisioning burst into one pass, short
/// enough that a single new link is forwarding within the time its
/// neighbours resolve.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Handle on the running watcher. Owned by `ActiveState`; `detach`
/// calls [`shutdown`](Self::shutdown) before it removes the pins the
/// watcher's map handles were opened from.
pub struct RedirectTargetWatcher {
    shutdown: CancellationToken,
    thread: Option<JoinHandle<()>>,
    directives: Arc<Mutex<Vec<ModuleDirective>>>,
}

impl RedirectTargetWatcher {
    /// Spawn the watcher thread. `directives` are the module's, for
    /// the `bridge-resolve` rule the VLAN derivation consults; a SIGHUP
    /// that changes them hands the new set over via
    /// [`set_directives`](Self::set_directives).
    ///
    /// `Err` only when the thread itself cannot be created. A netlink
    /// or map failure *inside* the thread is logged and ends it: attach
    /// stays up and the SIGHUP reconcile remains the fallback refresh,
    /// exactly as before this existed.
    pub fn start(bpffs_root: &Path, directives: Vec<ModuleDirective>) -> std::io::Result<Self> {
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let root = bpffs_root.to_path_buf();
        let directives = Arc::new(Mutex::new(directives));
        let shared = Arc::clone(&directives);
        let thread = std::thread::Builder::new()
            .name("pf-redirect-watch".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        warn!(
                            error = %e,
                            "redirect-target watcher: runtime build failed; REDIRECT_DEVMAP \
                             refreshes only on SIGHUP"
                        );
                        return;
                    }
                };
                rt.block_on(run(root, token, shared));
            })?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
            directives,
        })
    }

    /// Replace the directives the next topology refresh derives
    /// `VLAN_RESOLVE` from. Called by the SIGHUP reconcile after it has
    /// applied the same directives itself.
    pub fn set_directives(&self, directives: Vec<ModuleDirective>) {
        if let Ok(mut d) = self.directives.lock() {
            *d = directives;
        }
    }

    /// Stop the thread and wait for it. The map handles it holds are
    /// closed on return, so the caller may remove the pins afterwards.
    pub fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for RedirectTargetWatcher {
    fn drop(&mut self) {
        // A drop without `shutdown` (error unwinding in attach) must
        // not leave the thread running against pins that are about to
        // vanish. Cancel and let it exit on its own; joining inside
        // Drop would block whichever path dropped us.
        self.shutdown.cancel();
    }
}

/// The maps the watcher writes plus what it believes each holds.
///
/// Membership is tracked **per map**: a failed insert into one must
/// not mark the ifindex done for the other, or the failed side would
/// never be retried (every later `RTM_NEWLINK` would short-circuit on
/// the shared set) and the tc datapath would leak `pass_not_in_devmap`
/// until a SIGHUP (review finding).
struct Targets {
    devmap: DevMapHash<MapData>,
    tc: AyaHashMap<MapData, u32, u32>,
    vlan: AyaHashMap<MapData, u32, VlanResolve>,
    cfg: Array<MapData, FpCfg>,
    in_devmap: HashSet<u32>,
    in_tc: HashSet<u32>,
}

impl Targets {
    fn open(root: &Path) -> Result<Self, String> {
        let dm = MapData::from_pin(pin::map_path(root, "REDIRECT_DEVMAP"))
            .map_err(|e| format!("REDIRECT_DEVMAP pin open: {e}"))?;
        let devmap = DevMapHash::try_from(Map::DevMapHash(dm))
            .map_err(|e| format!("REDIRECT_DEVMAP try_from: {e}"))?;
        let tm = MapData::from_pin(pin::map_path(root, "TC_REDIRECT_TARGETS"))
            .map_err(|e| format!("TC_REDIRECT_TARGETS pin open: {e}"))?;
        let tc = AyaHashMap::try_from(Map::HashMap(tm))
            .map_err(|e| format!("TC_REDIRECT_TARGETS try_from: {e}"))?;
        let vm = MapData::from_pin(pin::map_path(root, "VLAN_RESOLVE"))
            .map_err(|e| format!("VLAN_RESOLVE pin open: {e}"))?;
        let vlan = AyaHashMap::try_from(Map::HashMap(vm))
            .map_err(|e| format!("VLAN_RESOLVE try_from: {e}"))?;
        let cm = MapData::from_pin(pin::map_path(root, "CFG"))
            .map_err(|e| format!("CFG pin open: {e}"))?;
        let cfg = Array::try_from(Map::Array(cm)).map_err(|e| format!("CFG try_from: {e}"))?;
        // Seed membership from what attach (or a previous SIGHUP) put
        // in each map.
        let in_devmap = devmap.keys().filter_map(Result::ok).collect();
        let in_tc = tc.keys().filter_map(Result::ok).collect();
        Ok(Self {
            devmap,
            tc,
            vlan,
            cfg,
            in_devmap,
            in_tc,
        })
    }

    fn admit(&mut self, ifindex: u32, why: &'static str) {
        let mut changed = false;
        if !self.in_devmap.contains(&ifindex) {
            match self.devmap.insert(ifindex, ifindex, None, 0) {
                Ok(()) => {
                    self.in_devmap.insert(ifindex);
                    changed = true;
                }
                Err(e) => warn!(ifindex, error = %e, "REDIRECT_DEVMAP insert failed"),
            }
        }
        if !self.in_tc.contains(&ifindex) {
            match self.tc.insert(ifindex, ifindex, 0) {
                Ok(()) => {
                    self.in_tc.insert(ifindex);
                    changed = true;
                }
                Err(e) => warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS insert failed"),
            }
        }
        if changed {
            info!(ifindex, why, "redirect target added");
        }
    }

    fn evict(&mut self, ifindex: u32, why: &'static str) {
        let mut changed = false;
        if self.in_devmap.remove(&ifindex) {
            changed = true;
            if let Err(e) = self.devmap.remove(ifindex) {
                warn!(ifindex, error = %e, "REDIRECT_DEVMAP remove failed");
            }
        }
        if self.in_tc.remove(&ifindex) {
            changed = true;
            if let Err(e) = self.tc.remove(&ifindex) {
                warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS remove failed");
            }
        }
        if changed {
            info!(ifindex, why, "redirect target removed");
        }
    }

    /// Bring `VLAN_RESOLVE` and its gate bit to what the topology says
    /// right now. `Err` means the topology could not be read; nothing
    /// was written and the caller should hold off admitting targets.
    fn refresh_vlan(&mut self, directives: &[ModuleDirective]) -> Result<(), String> {
        let want = desired_vlan_resolve(directives).map_err(|e| e.to_string())?;
        let delta = apply_vlan_resolve(&mut self.vlan, &want);
        let present = !(want.subifs.is_empty() && want.bridges.is_empty());
        // The SIGHUP path performs the same RMW on the same bit from
        // the main thread. Both write the value the topology dictates,
        // so an interleaving can at worst lose one update until the
        // next refresh or reload sets it again.
        if let Err(e) = set_cfg_flag_in(&mut self.cfg, FP_CFG_FLAG_VLAN_PRESENT, present) {
            warn!(error = %e, "VLAN_PRESENT gate write failed");
        }
        if delta.added > 0 || delta.removed > 0 {
            info!(
                added = delta.added,
                removed = delta.removed,
                present,
                "VLAN_RESOLVE refreshed from link events"
            );
        }
        Ok(())
    }

    /// Start-up pass: what `/sys/class/net` says versus what the maps
    /// hold — add what came up since the attach-time fill, purge what
    /// the kernel no longer knows. Same two rules as the SIGHUP
    /// reconcile.
    fn reconcile_targets(&mut self) {
        let desired: HashSet<u32> = enumerate_redirect_targets()
            .into_iter()
            .map(|(_, ifindex)| ifindex)
            .collect();
        let known: HashSet<u32> = self.in_devmap.union(&self.in_tc).copied().collect();
        let missing: Vec<u32> = desired.difference(&known).copied().collect();
        let stale: Vec<u32> = known
            .difference(&desired)
            .copied()
            .filter(|i| !ifindex_exists(*i))
            .collect();
        for ifindex in missing {
            self.admit(ifindex, "present at watcher start");
        }
        for ifindex in stale {
            self.evict(ifindex, "gone before watcher start");
        }
    }
}

/// The filter `enumerate_redirect_targets` applies to `/sys/class/net`,
/// applied to one `RTM_NEWLINK` instead: Ethernet-type and oper-up (or
/// `unknown`). Returns the ifindex when the link qualifies.
pub fn viable_target(link: &LinkMessage) -> Option<u32> {
    if link.header.link_layer_type != LinkLayerType::Ether {
        return None;
    }
    let oper = link.attributes.iter().find_map(|a| match a {
        LinkAttribute::OperState(s) => Some(s),
        _ => None,
    });
    match oper {
        Some(State::Up | State::Unknown) => Some(link.header.index),
        _ => None,
    }
}

/// Everything the debounced refresh needs to know about the events
/// since the last one.
#[derive(Default)]
struct Pending {
    /// Links that qualified as redirect targets, admitted only after
    /// `VLAN_RESOLVE` has been refreshed for them.
    admit: Vec<u32>,
    /// When the refresh is due; `None` when nothing changed.
    due: Option<Instant>,
}

impl Pending {
    fn touch(&mut self) {
        self.due = Some(Instant::now() + DEBOUNCE);
    }
}

async fn run(
    root: PathBuf,
    shutdown: CancellationToken,
    directives: Arc<Mutex<Vec<ModuleDirective>>>,
) {
    // Subscribe BEFORE the reconcile so a link that changes during the
    // reconcile is replayed from the socket buffer afterwards instead
    // of being missed (same ordering argument as the resolver's FDB
    // seed).
    let (conn, _handle, mut messages) = match new_multicast_connection(&[MulticastGroup::Link]) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                error = %e,
                "redirect-target watcher: RTNLGRP_LINK subscription failed; REDIRECT_DEVMAP \
                 refreshes only on SIGHUP"
            );
            return;
        }
    };
    tokio::spawn(conn);

    let mut targets = match Targets::open(&root) {
        Ok(t) => t,
        Err(e) => {
            warn!(
                error = %e,
                "redirect-target watcher: map open failed; REDIRECT_DEVMAP refreshes only on SIGHUP"
            );
            return;
        }
    };
    let mut pending = Pending::default();
    // First refresh right away: the attach-time fill is what the maps
    // hold, and this closes whatever moved between it and now.
    refresh(&mut targets, &mut pending, &directives);
    targets.reconcile_targets();
    info!(
        devmap = targets.in_devmap.len(),
        tc = targets.in_tc.len(),
        "redirect-target watcher live (RTNLGRP_LINK)"
    );

    loop {
        // The debounce arm exists only while something is pending.
        let due = pending.due;
        tokio::select! {
            _ = shutdown.cancelled() => {
                debug!("redirect-target watcher shutdown");
                return;
            }
            next = messages.next() => match next {
                Some((msg, _)) => handle(&mut targets, &mut pending, msg),
                None => {
                    warn!(
                        "redirect-target watcher: netlink stream closed; REDIRECT_DEVMAP \
                         refreshes only on SIGHUP"
                    );
                    return;
                }
            },
            _ = async { tokio::time::sleep_until(due.unwrap_or_else(Instant::now)).await }, if due.is_some() => {
                refresh(&mut targets, &mut pending, &directives);
            }
        }
    }
}

/// The debounced pass: `VLAN_RESOLVE` first, then the admits it was
/// holding back. A topology read failure keeps the admits pending and
/// re-arms the debounce, so a transient `/proc` error costs a retry,
/// not a redirect to an untranslated sub-interface.
fn refresh(
    targets: &mut Targets,
    pending: &mut Pending,
    directives: &Arc<Mutex<Vec<ModuleDirective>>>,
) {
    let snapshot: Vec<ModuleDirective> = match directives.lock() {
        Ok(d) => d.clone(),
        Err(_) => Vec::new(),
    };
    if let Err(e) = targets.refresh_vlan(&snapshot) {
        warn!(error = %e, "topology read failed; redirect admits held for retry");
        pending.touch();
        return;
    }
    pending.due = None;
    for ifindex in std::mem::take(&mut pending.admit) {
        // The link may have gone away again inside the debounce window.
        if ifindex_exists(ifindex) {
            targets.admit(ifindex, "RTM_NEWLINK");
        }
    }
}

fn handle(targets: &mut Targets, pending: &mut Pending, msg: NetlinkMessage<RouteNetlinkMessage>) {
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
            // Every NEWLINK can change the topology VLAN_RESOLVE is
            // derived from (a VLAN sub-interface, a bridge, a member
            // joining one), so it always schedules a refresh; only a
            // qualifying link is also queued for admission.
            if let Some(ifindex) = viable_target(&link) {
                if !pending.admit.contains(&ifindex) {
                    pending.admit.push(ifindex);
                }
            }
            pending.touch();
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
            let ifindex = link.header.index;
            pending.admit.retain(|i| *i != ifindex);
            targets.evict(ifindex, "RTM_DELLINK");
            pending.touch();
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(index: u32, kind: LinkLayerType, oper: Option<State>) -> LinkMessage {
        let mut m = LinkMessage::default();
        m.header.index = index;
        m.header.link_layer_type = kind;
        if let Some(s) = oper {
            m.attributes.push(LinkAttribute::OperState(s));
        }
        m
    }

    #[test]
    fn ethernet_up_or_unknown_is_a_target() {
        assert_eq!(
            viable_target(&link(7, LinkLayerType::Ether, Some(State::Up))),
            Some(7)
        );
        // Bridges and veths without carrier detection report `unknown`;
        // the attach-time fill accepts them, so this must too.
        assert_eq!(
            viable_target(&link(8, LinkLayerType::Ether, Some(State::Unknown))),
            Some(8)
        );
    }

    #[test]
    fn down_or_non_ethernet_is_not() {
        // Created-but-down: it becomes a target on the NEWLINK that
        // brings it up, not before.
        assert_eq!(
            viable_target(&link(9, LinkLayerType::Ether, Some(State::Down))),
            None
        );
        assert_eq!(
            viable_target(&link(10, LinkLayerType::Ether, Some(State::LowerLayerDown))),
            None
        );
        // No operstate attribute at all: not enough evidence to redirect.
        assert_eq!(viable_target(&link(11, LinkLayerType::Ether, None)), None);
        // Loopback (ARPHRD_LOOPBACK) and tunnels are never targets.
        assert_eq!(
            viable_target(&link(1, LinkLayerType::Loopback, Some(State::Unknown))),
            None
        );
    }
}
