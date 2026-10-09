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

/// A send error or a budget drop this recent makes a collector read as
/// failing.
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
    /// When the budget last dropped datagrams: samples lost on the way
    /// out, which a send after it does not undo.
    pub last_budget_drop: Option<Instant>,
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
            last_budget_drop: None,
        }
    }

    /// Why the collector reads as failing: a send error in the last
    /// [`FAILING_FOR`] with no send succeeding since, or datagrams the
    /// budget dropped in it.
    pub fn failing(&self, now: Instant) -> Option<String> {
        let recent = |at: Instant| now.saturating_duration_since(at) < FAILING_FOR;
        if let Some((at, why)) = &self.last_error {
            if recent(*at) && !self.last_ok.is_some_and(|ok| ok > *at) {
                return Some(format!("sends failing: {why}"));
            }
        }
        self.last_budget_drop
            .filter(|at| recent(*at))
            .map(|_| "datagrams dropped: the per-tick send budget was spent".to_owned())
    }
}

/// Send each datagram to every collector `to` selects, within each one's
/// budget.
pub fn send_all(
    t: &dyn Transport,
    collectors: &mut [CollectorState],
    to: impl Fn(&Collector) -> bool,
    datagrams: &[Vec<u8>],
    now: Instant,
) {
    if datagrams.is_empty() {
        return;
    }
    for c in collectors.iter_mut().filter(|c| to(&c.cfg)) {
        for (i, d) in datagrams.iter().enumerate() {
            if i >= SEND_BUDGET {
                c.budget_drops += (datagrams.len() - i) as u64;
                c.last_budget_drop = Some(now);
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

/// Send every datagram to each collector `to` selects, without the
/// per-tick budget: the export is stopping, and what it holds goes now or
/// not at all. A full socket buffer is waited out until `deadline`. The
/// datagrams not sent to some collector by then are returned, and not
/// tried.
pub fn send_until(
    t: &dyn Transport,
    collectors: &mut [CollectorState],
    to: impl Fn(&Collector) -> bool,
    datagrams: &[Vec<u8>],
    deadline: Instant,
) -> usize {
    for (i, d) in datagrams.iter().enumerate() {
        for c in collectors.iter_mut().filter(|c| to(&c.cfg)) {
            loop {
                let now = Instant::now();
                match t.send_to(d, c.cfg.addr) {
                    Ok(_) => {
                        c.datagrams += 1;
                        c.last_ok = Some(now);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && now < deadline => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => {
                        c.send_errors += 1;
                        c.last_error = Some((now, e.to_string()));
                    }
                }
                break;
            }
        }
        if Instant::now() >= deadline {
            return datagrams.len() - i - 1;
        }
    }
    0
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

    const TICK_LATER: Duration = Duration::from_millis(100);

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
            format: packetframe_common::config::CollectorFormat::Sflow,
            profile: Default::default(),
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
        send_all(&t, &mut cs, |_| true, &[vec![0; 10], vec![0; 10]], now);
        assert_eq!((cs[0].datagrams, cs[0].send_errors), (2, 0));
        assert_eq!((cs[1].datagrams, cs[1].send_errors), (0, 2));
        assert!(cs[0].failing(now).is_none());
        assert!(cs[1].failing(now).unwrap().contains("unreachable"));
        assert!(cs[1].failing(now + FAILING_FOR).is_none(), "old news");
    }

    /// A socket whose buffer is full for the first `blocked` sends.
    struct Busy {
        blocked: std::cell::Cell<u32>,
        sent: std::cell::Cell<usize>,
    }

    impl Transport for Busy {
        fn send_to(&self, buf: &[u8], _: SocketAddr) -> io::Result<usize> {
            if self.blocked.get() > 0 {
                self.blocked.set(self.blocked.get() - 1);
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.sent.set(self.sent.get() + 1);
            Ok(buf.len())
        }
    }

    #[test]
    fn stopping_sends_past_the_budget_and_waits_out_a_full_buffer() {
        let mut cs = vec![CollectorState::new(c("a", 1))];
        let burst = vec![vec![0u8; 1]; SEND_BUDGET + 7];
        let t = Busy {
            blocked: 3.into(),
            sent: 0.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        assert_eq!(send_until(&t, &mut cs, |_| true, &burst, deadline), 0);
        assert_eq!(t.sent.get(), burst.len());
        assert_eq!(cs[0].send_errors, 0, "a full buffer waited out is no error");

        // A buffer that stays full: the deadline ends the wait.
        let t = Busy {
            blocked: u32::MAX.into(),
            sent: 0.into(),
        };
        let unsent = send_until(&t, &mut cs, |_| true, &burst, Instant::now());
        assert_eq!(unsent, burst.len() - 1);
        assert_eq!(cs[0].send_errors, 1);
    }

    #[test]
    fn the_budget_bounds_a_burst_and_is_counted() {
        let mut cs = vec![CollectorState::new(c("a", 1))];
        let t = Fake {
            fail_to: None,
            sent: RefCell::new(Vec::new()),
        };
        let burst = vec![vec![0u8; 1]; SEND_BUDGET + 7];
        let now = Instant::now();
        send_all(&t, &mut cs, |_| true, &burst, now);
        assert_eq!(cs[0].datagrams, SEND_BUDGET as u64);
        assert_eq!(cs[0].budget_drops, 7);
        // Samples lost on the way out: failing, though every send it made
        // succeeded, until the drops are old news.
        assert!(cs[0].failing(now).unwrap().contains("budget"));
        send_all(&t, &mut cs, |_| true, &[vec![0u8; 1]], now + TICK_LATER);
        assert!(cs[0].failing(now + TICK_LATER).is_some());
        assert!(cs[0].failing(now + FAILING_FOR).is_none());
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
