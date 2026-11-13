//! The resolver's synthesized routes, applied without holding the
//! resolver.
//!
//! ## Why
//!
//! The neighbour resolver makes routes of its own: a `/32` or `/128` for
//! each host it learns inside a `local-prefix`, the `fallback-default`
//! `0.0.0.0/0`, and a `PeerDown` when a link goes. Each is a command to
//! the [`FibProgrammer`](super::programmer), and the programmer takes no
//! command while it applies a route-ledger seed or a walk: no route event
//! may overtake either. The resolver used to await each one, so the first
//! such route at start parked it behind the whole seed. It answered no
//! resolve request meanwhile, and every next hop the seed registered sat
//! unresolved until the seed ended. On the reference deployment after the
//! 6.0.17 upgrade (2026-11-12) that was 73 s, with 1.1M routes behind one
//! transit next hop the resolver never got to (`nexthop_resolve_slow`,
//! `not-served`).
//!
//! ## What it does
//!
//! The resolver hands each synthesized route to a [`RouteApplier`] and
//! goes on serving. The applier is a task of its own that applies them
//! one at a time, in the order they were handed over, awaiting each answer
//! as the resolver did; only the resolver no longer waits for it. The
//! programmer's own command queue, which the BGP feed fills during a
//! seed, is waited on here instead.
//!
//! ## Bounded by coalescing
//!
//! The resolver must never block on the applier, and a queue that kept
//! every transition would grow for as long as a seed holds the programmer,
//! by however much neighbour churn the segment produces (review finding on
//! #393). Every transition is applied in order while the queue is short.
//! Once it backs up (4,096 jobs, then twice what the last compaction
//! left) it is compacted to one job per route, a host route's `ip`, the
//! fallback default or a link's `PeerDown`: the last one, where it stands.
//! Only the latest state of a route matters (an Add upserts, a Del
//! withdraws), and the kept job stays after every other route's job that
//! came before it, a `PeerDown` included. The queue is then bounded by
//! twice the routes the resolver can make: one per neighbour in a
//! `local-prefix`, plus one per link.
//!
//! ## A Learned after its Add
//!
//! The startup host seed follows each Add with a `Learned` carrying the
//! cached MAC (see `seed_local_prefix_routes`). The programmer discards a
//! `Learned` for a nexthop it has not registered, and the Add is what
//! registers it, so the `Learned` goes with the Add's job and is sent to
//! the programmer's neighbour channel only once the Add is applied
//! (review finding on #393).
//!
//! The applier does not hold the resolver's "waiting on the
//! FibProgrammer" marker: that marker excuses the resolver's own stall
//! detector, and a backlog of routes here, expected while a seed applies,
//! must not hide a resolver that has really stopped. The backlog is in
//! the resolver's stats line instead (`synth_routes_pending`).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

use packetframe_common::fib::{NeighEvent, RouteEvent};

use super::programmer::FibProgrammerHandle;

/// What a route is, for its counter and its log line.
#[derive(Debug, Clone)]
pub enum RouteKind {
    /// A `local-prefix` host route for `ip`.
    HostAdd { ip: IpAddr },
    /// Its withdrawal.
    HostDel { ip: IpAddr },
    /// The `fallback-default` `/0` via `nexthop` on `iface`; `resend` when
    /// the same ifindex was already handed over.
    Fallback {
        iface: String,
        ifindex: u32,
        nexthop: IpAddr,
        resend: bool,
    },
    /// A departed link's `PeerDown`.
    PeerDown {
        ifindex: u32,
        carried_fallback: bool,
    },
}

/// Which route a job is for: a newer job for the same key replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Host(IpAddr),
    Fallback,
    PeerDown(u32),
}

impl RouteKind {
    fn key(&self) -> Key {
        match self {
            Self::HostAdd { ip } | Self::HostDel { ip } => Key::Host(*ip),
            Self::Fallback { .. } => Key::Fallback,
            Self::PeerDown { ifindex, .. } => Key::PeerDown(*ifindex),
        }
    }
}

/// One route to apply, and the neighbour event to send once it is.
#[derive(Debug)]
struct Job {
    event: RouteEvent,
    kind: RouteKind,
    then: Option<NeighEvent>,
}

/// Jobs waiting before the queue is first compacted.
const COMPACT_AT: usize = 4096;

/// The waiting jobs, in hand-over order.
#[derive(Debug)]
struct Queue {
    jobs: VecDeque<Job>,
    /// The length at which the next push compacts. Never below the floor,
    /// and twice what the last compaction left, so a queue of mostly
    /// distinct routes is not rescanned on every push.
    compact_at: usize,
    floor: usize,
    closed: bool,
}

impl Default for Queue {
    fn default() -> Self {
        Self::with_floor(COMPACT_AT)
    }
}

impl Queue {
    fn with_floor(floor: usize) -> Self {
        Self {
            jobs: VecDeque::new(),
            compact_at: floor,
            floor,
            closed: false,
        }
    }

    /// Queue `job` at the back. Returns how many waiting jobs a
    /// compaction dropped (0 unless the queue had backed up).
    fn push(&mut self, job: Job) -> usize {
        let dropped = if self.jobs.len() >= self.compact_at {
            self.compact()
        } else {
            0
        };
        self.jobs.push_back(job);
        dropped
    }

    /// Keep only the last job for each route, where it stands. That is
    /// the same as replacing each earlier one and moving it to the back:
    /// only a route's latest state matters (an Add upserts, a Del
    /// withdraws), and the kept job stays after every other route's job
    /// that came before it, a `PeerDown` included.
    ///
    /// A host route's kept Add takes the seed's `Learned` from an earlier
    /// Add it replaces, unless a Del came between: the Learned is still
    /// the nexthop's only resolution.
    fn compact(&mut self) -> usize {
        let before = self.jobs.len();
        let mut last: HashMap<Key, usize> = HashMap::with_capacity(before);
        for (i, j) in self.jobs.iter().enumerate() {
            last.insert(j.kind.key(), i);
        }
        let mut learned: HashMap<Key, NeighEvent> = HashMap::new();
        let mut kept = VecDeque::with_capacity(last.len());
        for (i, mut j) in std::mem::take(&mut self.jobs).into_iter().enumerate() {
            let key = j.kind.key();
            match j.kind {
                RouteKind::HostAdd { .. } => {
                    if let Some(t) = j.then.take() {
                        learned.insert(key, t);
                    }
                }
                RouteKind::HostDel { .. } => {
                    learned.remove(&key);
                }
                _ => {}
            }
            if last.get(&key) == Some(&i) {
                if matches!(j.kind, RouteKind::HostAdd { .. }) {
                    j.then = learned.remove(&key);
                }
                kept.push_back(j);
            }
        }
        self.jobs = kept;
        self.compact_at = self.floor.max(self.jobs.len() * 2);
        before - self.jobs.len()
    }

    fn pop(&mut self) -> Option<Job> {
        self.jobs.pop_front()
    }
}

/// What the applier has done, for the resolver's stats line.
#[derive(Debug, Default)]
pub struct ApplierStats {
    pub host_v4_added: AtomicU64,
    pub host_v4_removed: AtomicU64,
    pub host_v6_added: AtomicU64,
    pub host_v6_removed: AtomicU64,
    /// Waiting or being applied.
    pub pending: AtomicU64,
    /// Jobs a newer one for the same route replaced before they ran, in a
    /// backed-up queue.
    pub coalesced: AtomicU64,
    pub failed: AtomicU64,
}

/// The resolver's side: hand a route over and carry on.
pub struct RouteApplier {
    queue: Arc<Mutex<Queue>>,
    wake: Arc<Notify>,
    stats: Arc<ApplierStats>,
}

impl RouteApplier {
    /// Start the applier task on the current runtime. `events_tx` is the
    /// programmer's neighbour channel, for a job's follow-up `Learned`.
    pub fn spawn(prog: FibProgrammerHandle, events_tx: mpsc::Sender<NeighEvent>) -> Self {
        let queue = Arc::new(Mutex::new(Queue::default()));
        let wake = Arc::new(Notify::new());
        let stats = Arc::new(ApplierStats::default());
        let (q, w, counts) = (queue.clone(), wake.clone(), stats.clone());
        tokio::spawn(async move {
            loop {
                let next = {
                    let mut g = q.lock().unwrap_or_else(|e| e.into_inner());
                    match g.pop() {
                        Some(job) => Some(job),
                        None if g.closed => return,
                        None => None,
                    }
                };
                let Some(job) = next else {
                    // `notify_one` stores a permit when nobody waits, so a
                    // job queued between the pop and here is not missed.
                    w.notified().await;
                    continue;
                };
                let result = prog.apply_route_event(job.event).await;
                if result.is_ok() {
                    if let Some(evt) = job.then {
                        if events_tx.send(evt).await.is_err() {
                            debug!("programmer gone; a seeded Learned was dropped at shutdown");
                        }
                    }
                }
                counts.pending.fetch_sub(1, Ordering::Relaxed);
                settle(&counts, &job.kind, result);
            }
        });
        Self { queue, wake, stats }
    }

    /// Queue `event` behind every route handed over before it. Never
    /// waits; a backed-up queue drops the waiting jobs a newer one for the
    /// same route supersedes.
    pub fn submit(&self, event: RouteEvent, kind: RouteKind) {
        self.push(Job {
            event,
            kind,
            then: None,
        });
    }

    /// As [`Self::submit`], and send `then` to the programmer's neighbour
    /// channel once `event` is applied: the seed's `Learned` after its Add.
    pub fn submit_then(&self, event: RouteEvent, kind: RouteKind, then: NeighEvent) {
        self.push(Job {
            event,
            kind,
            then: Some(then),
        });
    }

    fn push(&self, job: Job) {
        let dropped = {
            let mut g = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            g.push(job)
        } as u64;
        self.stats.pending.fetch_add(1, Ordering::Relaxed);
        if dropped > 0 {
            self.stats.pending.fetch_sub(dropped, Ordering::Relaxed);
            self.stats.coalesced.fetch_add(dropped, Ordering::Relaxed);
        }
        self.wake.notify_one();
    }

    pub fn stats(&self) -> &ApplierStats {
        &self.stats
    }
}

impl Drop for RouteApplier {
    /// The resolver is gone: apply what is queued, then stop.
    fn drop(&mut self) {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.wake.notify_one();
    }
}

fn settle(
    counts: &ApplierStats,
    kind: &RouteKind,
    result: Result<(), super::programmer::ProgrammerError>,
) {
    match (kind, result) {
        (RouteKind::HostAdd { ip }, Ok(())) => {
            let c = if ip.is_ipv4() {
                &counts.host_v4_added
            } else {
                &counts.host_v6_added
            };
            c.fetch_add(1, Ordering::Relaxed);
        }
        (RouteKind::HostDel { ip }, Ok(())) => {
            let c = if ip.is_ipv4() {
                &counts.host_v4_removed
            } else {
                &counts.host_v6_removed
            };
            c.fetch_add(1, Ordering::Relaxed);
        }
        (
            RouteKind::Fallback {
                iface,
                ifindex,
                nexthop,
                resend,
            },
            Ok(()),
        ) => {
            if *resend {
                debug!(%iface, ifindex, "fallback-default 0.0.0.0/0 re-sent on RTM_NEWLINK");
            } else {
                info!(%iface, ifindex, %nexthop, "v0.2.1 fallback-default 0.0.0.0/0 injected");
            }
        }
        (
            RouteKind::PeerDown {
                ifindex,
                carried_fallback: true,
            },
            Ok(()),
        ) => info!(
            ifindex,
            "fallback-default iface deleted; 0.0.0.0/0 withdrawn until its RTM_NEWLINK"
        ),
        (RouteKind::PeerDown { .. }, Ok(())) => {}
        (kind, Err(e)) => {
            counts.failed.fetch_add(1, Ordering::Relaxed);
            match kind {
                RouteKind::HostAdd { ip } => {
                    warn!(?ip, error = %e, "local-prefix RouteEvent::Add dispatch failed")
                }
                RouteKind::HostDel { ip } => {
                    warn!(?ip, error = %e, "local-prefix RouteEvent::Del dispatch failed")
                }
                RouteKind::Fallback { iface, ifindex, .. } => {
                    warn!(%iface, ifindex, error = %e, "fallback-default injection failed")
                }
                RouteKind::PeerDown { ifindex, .. } => {
                    warn!(ifindex, error = %e, "local_arp RouteEvent::PeerDown dispatch failed")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::fib::PeerId;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    fn add(n: u8) -> Job {
        Job {
            event: RouteEvent::Del {
                peer_id: PeerId(1),
                prefix: packetframe_common::fib::IpPrefix::V4 {
                    addr: [192, 0, 2, n],
                    prefix_len: 32,
                },
                path_id: None,
            },
            kind: RouteKind::HostAdd { ip: ip(n) },
            then: None,
        }
    }

    fn del(n: u8) -> Job {
        Job {
            kind: RouteKind::HostDel { ip: ip(n) },
            ..add(n)
        }
    }

    fn peer_down(ifindex: u32) -> Job {
        Job {
            kind: RouteKind::PeerDown {
                ifindex,
                carried_fallback: false,
            },
            ..add(0)
        }
    }

    fn drain(q: &mut Queue) -> Vec<String> {
        std::iter::from_fn(|| q.pop())
            .map(|j| match j.kind {
                RouteKind::HostAdd { ip } => format!("add {ip}"),
                RouteKind::HostDel { ip } => format!("del {ip}"),
                RouteKind::PeerDown { ifindex, .. } => format!("down {ifindex}"),
                RouteKind::Fallback { .. } => "fallback".into(),
            })
            .collect()
    }

    #[test]
    fn a_short_queue_applies_every_transition_in_order() {
        let mut q = Queue::default();
        q.push(add(7));
        q.push(del(7));
        q.push(add(7));
        assert_eq!(
            drain(&mut q),
            vec!["add 192.0.2.7", "del 192.0.2.7", "add 192.0.2.7"]
        );
    }

    #[test]
    fn churn_in_a_backed_up_queue_stays_bounded() {
        let mut q = Queue::default();
        let mut dropped = 0;
        for _ in 0..10_000 {
            dropped += q.push(add(7));
            dropped += q.push(del(7));
        }
        assert!(q.jobs.len() <= COMPACT_AT + 1, "{}", q.jobs.len());
        assert_eq!(dropped + q.jobs.len(), 20_000);
        assert_eq!(drain(&mut q).last().unwrap(), "del 192.0.2.7");
    }

    #[test]
    fn compaction_keeps_each_routes_last_job_where_it_stands() {
        // Del, then the link goes, then the host comes back: the Add must
        // land after the PeerDown or the PeerDown would withdraw it.
        let mut q = Queue::with_floor(3);
        q.push(del(7));
        q.push(peer_down(3));
        q.push(add(7));
        q.push(add(8));
        assert_eq!(
            drain(&mut q),
            vec!["down 3", "add 192.0.2.7", "add 192.0.2.8"]
        );
    }

    #[test]
    fn compaction_keeps_the_seeds_learned_on_a_re_add_but_not_past_a_del() {
        let learned = |n| NeighEvent::Learned {
            ip: ip(n),
            mac: [2; 6],
            ifindex: 3,
            src_mac: [0; 6],
        };
        let mut q = Queue::with_floor(4);
        q.push(Job {
            then: Some(learned(7)),
            ..add(7)
        });
        q.push(add(7));
        q.push(Job {
            then: Some(learned(8)),
            ..add(8)
        });
        q.push(del(8));
        q.push(add(8)); // compacts the four before it
        let jobs: Vec<Job> = std::iter::from_fn(|| q.pop()).collect();
        let then_of = |n: u8| {
            jobs.iter()
                .find(|j| matches!(j.kind, RouteKind::HostAdd { ip: i } if i == ip(n)))
                .map(|j| j.then.is_some())
        };
        assert_eq!(then_of(7), Some(true), "a re-add keeps it");
        // 8's Add after its Del stands alone, behind it; the Learned that
        // came before the Del is gone.
        assert_eq!(jobs.len(), 3);
        assert_eq!(then_of(8), Some(false));
    }
}
