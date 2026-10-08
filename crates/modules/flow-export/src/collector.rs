//! Sending datagrams to collectors.
//!
//! What PacketFrame can know is local submission: the send succeeded.
//! Receipt is the collector's to know, and every report here says so;
//! nothing downstream may read a successful send as delivery.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::cfg::Collector;

/// Datagrams each collector may be sent per worker tick (100 ms): ample
/// for 1:1000 on every port at once, and a bound on what a burst costs.
pub const SEND_BUDGET: usize = 512;

/// A send error this recent makes a collector read as failing.
pub const FAILING_FOR: Duration = Duration::from_secs(10);

/// The socket, behind a trait for the tests to fail it.
pub trait Transport {
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize>;
}

impl Transport for std::net::UdpSocket {
    fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        std::net::UdpSocket::send_to(self, buf, to)
    }
}

#[derive(Debug, Clone)]
pub struct CollectorState {
    pub cfg: Collector,
    pub datagrams: u64,
    pub send_errors: u64,
    /// Datagrams not sent because the tick's budget was spent.
    pub budget_drops: u64,
    pub last_error: Option<(Instant, String)>,
    pub last_ok: Option<Instant>,
}

impl CollectorState {
    pub fn new(cfg: Collector) -> Self {
        Self {
            cfg,
            datagrams: 0,
            send_errors: 0,
            budget_drops: 0,
            last_error: None,
            last_ok: None,
        }
    }

    /// The last [`FAILING_FOR`]'s most recent send error, if no send
    /// has succeeded since.
    pub fn failing(&self, now: Instant) -> Option<&str> {
        let (at, why) = self.last_error.as_ref()?;
        let recent = now.saturating_duration_since(*at) < FAILING_FOR;
        let recovered = self.last_ok.is_some_and(|ok| ok > *at);
        (recent && !recovered).then_some(why.as_str())
    }
}

/// Send each datagram to every collector, within each one's budget.
pub fn send_all(
    t: &dyn Transport,
    collectors: &mut [CollectorState],
    datagrams: &[Vec<u8>],
    now: Instant,
) {
    for c in collectors.iter_mut() {
        for (i, d) in datagrams.iter().enumerate() {
            if i >= SEND_BUDGET {
                c.budget_drops += (datagrams.len() - i) as u64;
                break;
            }
            match t.send_to(d, c.cfg.addr) {
                Ok(_) => {
                    c.datagrams += 1;
                    c.last_ok = Some(now);
                }
                Err(e) => {
                    c.send_errors += 1;
                    c.last_error = Some((now, e.to_string()));
                }
            }
        }
    }
}

/// Carry each collector's counters across a reload that keeps it (same
/// name, address and kind); a new or changed one starts from zero.
pub fn reconcile(old: Vec<CollectorState>, new: &[Collector]) -> Vec<CollectorState> {
    let mut old = old;
    new.iter()
        .map(|c| match old.iter().position(|o| &o.cfg == c) {
            Some(i) => old.swap_remove(i),
            None => CollectorState::new(c.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::CollectorKind;
    use std::cell::RefCell;

    struct Fake {
        fail_to: Option<SocketAddr>,
        sent: RefCell<Vec<SocketAddr>>,
    }

    impl Transport for Fake {
        fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
            if Some(to) == self.fail_to {
                return Err(io::Error::from_raw_os_error(libc::ENETUNREACH));
            }
            self.sent.borrow_mut().push(to);
            Ok(buf.len())
        }
    }

    fn c(name: &str, port: u16) -> Collector {
        Collector {
            name: name.into(),
            addr: format!("198.51.100.1:{port}").parse().unwrap(),
            kind: CollectorKind::Stats,
        }
    }

    #[test]
    fn every_collector_gets_every_datagram_and_failures_are_its_own() {
        let mut cs = vec![
            CollectorState::new(c("a", 1)),
            CollectorState::new(c("b", 2)),
        ];
        let t = Fake {
            fail_to: Some(cs[1].cfg.addr),
            sent: RefCell::new(Vec::new()),
        };
        let now = Instant::now();
        send_all(&t, &mut cs, &[vec![0; 10], vec![0; 10]], now);
        assert_eq!((cs[0].datagrams, cs[0].send_errors), (2, 0));
        assert_eq!((cs[1].datagrams, cs[1].send_errors), (0, 2));
        assert!(cs[0].failing(now).is_none());
        assert!(cs[1].failing(now).unwrap().contains("unreachable"));
        assert!(cs[1].failing(now + FAILING_FOR).is_none(), "old news");
    }

    #[test]
    fn the_budget_bounds_a_burst_and_is_counted() {
        let mut cs = vec![CollectorState::new(c("a", 1))];
        let t = Fake {
            fail_to: None,
            sent: RefCell::new(Vec::new()),
        };
        let burst = vec![vec![0u8; 1]; SEND_BUDGET + 7];
        send_all(&t, &mut cs, &burst, Instant::now());
        assert_eq!(cs[0].datagrams, SEND_BUDGET as u64);
        assert_eq!(cs[0].budget_drops, 7);
    }

    #[test]
    fn a_reload_keeps_the_counters_of_collectors_it_keeps() {
        let mut a = CollectorState::new(c("a", 1));
        a.datagrams = 9;
        let kept = reconcile(
            vec![a, CollectorState::new(c("b", 2))],
            &[c("a", 1), c("z", 3)],
        );
        assert_eq!(kept[0].datagrams, 9);
        assert_eq!((kept[1].cfg.name.as_str(), kept[1].datagrams), ("z", 0));
    }
}
