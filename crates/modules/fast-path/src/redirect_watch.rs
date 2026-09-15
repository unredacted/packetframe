//! Keeps the redirect-target maps in step with the kernel's link table
//! for the life of the attach.
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
//! This watcher subscribes to `RTNLGRP_LINK` on its own thread, brings
//! both maps up to date once the subscription is live (so nothing can
//! slip between the attach-time fill and the first event), then adds a
//! target on every `RTM_NEWLINK` for an oper-up Ethernet-type link and
//! removes it on `RTM_DELLINK`. It works from the bpffs pins like the
//! rest of the control plane and runs in every forwarding mode: the
//! pre-check is the same under kernel-fib and custom-fib.
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
use std::thread::JoinHandle;

use aya::maps::{xdp::DevMapHash, HashMap as AyaHashMap, Map, MapData};
use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::link::{LinkAttribute, LinkLayerType, LinkMessage, State};
use netlink_packet_route::RouteNetlinkMessage;
use rtnetlink::{new_multicast_connection, MulticastGroup};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::linux_impl::enumerate_redirect_targets;
use crate::pin;
use crate::reconcile::ifindex_exists;

/// Handle on the running watcher. Owned by `ActiveState`; `detach`
/// calls [`shutdown`](Self::shutdown) before it removes the pins the
/// watcher's map handles were opened from.
pub struct RedirectTargetWatcher {
    shutdown: CancellationToken,
    thread: Option<JoinHandle<()>>,
}

impl RedirectTargetWatcher {
    /// Spawn the watcher thread. `Err` only when the thread itself
    /// cannot be created. A netlink or map failure *inside* the thread
    /// is logged and ends it: attach stays up and the SIGHUP reconcile
    /// remains the fallback refresh, exactly as before this existed.
    pub fn start(bpffs_root: &Path) -> std::io::Result<Self> {
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let root = bpffs_root.to_path_buf();
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
                rt.block_on(run(root, token));
            })?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
        })
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

/// Both redirect-target maps plus the membership the watcher believes
/// they hold, so an event that changes nothing costs no syscall and
/// produces no log line.
struct Targets {
    devmap: DevMapHash<MapData>,
    tc: AyaHashMap<MapData, u32, u32>,
    members: HashSet<u32>,
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
        // Seed membership from what attach (or a previous SIGHUP) put
        // in the devmap; the tc mirror is written in lockstep and is
        // not read back.
        let members = devmap.keys().filter_map(Result::ok).collect();
        Ok(Self {
            devmap,
            tc,
            members,
        })
    }

    fn add(&mut self, ifindex: u32, why: &'static str) {
        if self.members.contains(&ifindex) {
            return;
        }
        if let Err(e) = self.devmap.insert(ifindex, ifindex, None, 0) {
            warn!(ifindex, error = %e, "REDIRECT_DEVMAP insert failed");
            return;
        }
        if let Err(e) = self.tc.insert(ifindex, ifindex, 0) {
            warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS insert failed");
        }
        self.members.insert(ifindex);
        info!(ifindex, why, "redirect target added");
    }

    fn remove(&mut self, ifindex: u32, why: &'static str) {
        if !self.members.remove(&ifindex) {
            return;
        }
        if let Err(e) = self.devmap.remove(ifindex) {
            warn!(ifindex, error = %e, "REDIRECT_DEVMAP remove failed");
        }
        if let Err(e) = self.tc.remove(&ifindex) {
            warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS remove failed");
        }
        info!(ifindex, why, "redirect target removed");
    }

    /// Bring the maps to what `/sys/class/net` says right now: add
    /// what came up since the attach-time fill, purge what the kernel
    /// no longer knows. Same two rules as the SIGHUP reconcile.
    fn reconcile(&mut self) {
        let desired: HashSet<u32> = enumerate_redirect_targets()
            .into_iter()
            .map(|(_, ifindex)| ifindex)
            .collect();
        let missing: Vec<u32> = desired.difference(&self.members).copied().collect();
        let stale: Vec<u32> = self
            .members
            .difference(&desired)
            .copied()
            .filter(|i| !ifindex_exists(*i))
            .collect();
        for ifindex in missing {
            self.add(ifindex, "present at watcher start");
        }
        for ifindex in stale {
            self.remove(ifindex, "gone before watcher start");
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

async fn run(root: PathBuf, shutdown: CancellationToken) {
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
    targets.reconcile();
    info!(
        members = targets.members.len(),
        "redirect-target watcher live (RTNLGRP_LINK)"
    );

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                debug!("redirect-target watcher shutdown");
                return;
            }
            next = messages.next() => match next {
                Some((msg, _)) => handle(&mut targets, msg),
                None => {
                    warn!(
                        "redirect-target watcher: netlink stream closed; REDIRECT_DEVMAP \
                         refreshes only on SIGHUP"
                    );
                    return;
                }
            }
        }
    }
}

fn handle(targets: &mut Targets, msg: NetlinkMessage<RouteNetlinkMessage>) {
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
            if let Some(ifindex) = viable_target(&link) {
                targets.add(ifindex, "RTM_NEWLINK");
            }
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
            targets.remove(link.header.index, "RTM_DELLINK");
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
