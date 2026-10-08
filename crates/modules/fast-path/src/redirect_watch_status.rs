//! What the redirect-target watcher (`redirect_watch`, Linux-only)
//! reports about itself: whether it still follows the link table, how
//! often the kernel dropped link notifications on it, and how many
//! qualifying links the redirect maps refused. Portable, so the
//! `redirect-watch` status row and its gauges are tested on every host.

use std::fmt::Write as _;

use packetframe_common::module::{HealthState, SubsystemHealth};

pub const SUBSYSTEM_NAME: &str = "redirect-watch";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchStatus {
    /// Why the watcher stopped for good; `None` while it runs. Once it
    /// has stopped, `REDIRECT_DEVMAP`, `TC_REDIRECT_TARGETS`,
    /// `VLAN_RESOLVE` and `RX_MACS` follow the link table only on SIGHUP.
    pub stopped: Option<String>,
    /// Times the kernel reported link notifications lost to a full
    /// receive buffer (`ENOBUFS`). One report stands for any number.
    pub overruns: u64,
    /// Recoveries from lost notifications: `ok` once a re-read has been
    /// read and every admission it queued attempted, `failed` for each
    /// dump that failed.
    pub resyncs_ok: u64,
    pub resyncs_failed: u64,
    /// Notifications were lost and no completed recovery covers them yet.
    pub resync_pending: bool,
    /// Why the recovery has not finished: the dump failed, or the link
    /// topology could not be read to apply it. Cleared by a completed
    /// recovery.
    pub last_resync_error: Option<String>,
    /// Qualifying links whose insert into a redirect map was refused —
    /// in practice, the maps are full (64 links each). Recomputed on every
    /// refresh, whatever the overrun history; their traffic takes the
    /// kernel path until an eviction makes room.
    pub unadmitted: u64,
}

impl WatchStatus {
    fn refused_text(&self) -> String {
        format!(
            "{} qualifying links are not in the redirect maps: their insert was refused (the \
             maps hold 64 links each, so usually they are full); their traffic takes the \
             kernel path until an eviction makes room",
            self.unadmitted
        )
    }

    pub fn subsystem_health(&self) -> SubsystemHealth {
        let (state, message) = if let Some(why) = &self.stopped {
            (
                HealthState::Degraded,
                format!(
                    "stopped ({why}); the redirect maps follow the link table only on SIGHUP, \
                     so a link created or re-created since stays on the kernel path \
                     (pass_not_in_devmap)"
                ),
            )
        } else if self.resync_pending {
            let mut m = format!(
                "link notifications lost ({} overruns); a link created or deleted meanwhile is \
                 missing from the redirect maps until the link table is re-read",
                self.overruns
            );
            if let Some(e) = &self.last_resync_error {
                let _ = write!(m, "; not recovered yet (retrying): {e}");
            }
            if self.unadmitted > 0 {
                let _ = write!(m, "; {}", self.refused_text());
            }
            (HealthState::Degraded, m)
        } else if self.unadmitted > 0 {
            (HealthState::Degraded, self.refused_text())
        } else {
            let mut m = "following the link table".to_string();
            if self.overruns > 0 {
                let _ = write!(
                    m,
                    "; {} notification overruns, each made good by a re-read",
                    self.overruns
                );
            }
            (HealthState::Healthy, m)
        };
        SubsystemHealth {
            name: SUBSYSTEM_NAME.to_string(),
            state,
            message: Some(message),
            last_success_age_seconds: None,
        }
    }

    /// Textfile gauges: whether the watcher runs, its overruns and its
    /// re-reads.
    pub fn render_metrics(&self, out: &mut String) {
        let _ = writeln!(
            out,
            "# HELP packetframe_redirect_watch_running 1 while the redirect-target watcher follows the link table"
        );
        let _ = writeln!(out, "# TYPE packetframe_redirect_watch_running gauge");
        let _ = writeln!(
            out,
            "packetframe_redirect_watch_running{{module=\"fast-path\"}} {}",
            u8::from(self.stopped.is_none())
        );
        let _ = writeln!(
            out,
            "# HELP packetframe_redirect_watch_overruns_total times the kernel reported link notifications lost to a full receive buffer"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_redirect_watch_overruns_total counter"
        );
        let _ = writeln!(
            out,
            "packetframe_redirect_watch_overruns_total{{module=\"fast-path\"}} {}",
            self.overruns
        );
        let _ = writeln!(
            out,
            "# HELP packetframe_redirect_watch_resyncs_total recoveries from lost link notifications (ok: re-read and applied; failed: a dump that failed)"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_redirect_watch_resyncs_total counter"
        );
        for (outcome, n) in [("ok", self.resyncs_ok), ("failed", self.resyncs_failed)] {
            let _ = writeln!(
                out,
                "packetframe_redirect_watch_resyncs_total{{module=\"fast-path\",outcome=\"{outcome}\"}} {n}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP packetframe_redirect_watch_unadmitted_links qualifying links the redirect maps refused (usually: full)"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_redirect_watch_unadmitted_links gauge"
        );
        let _ = writeln!(
            out,
            "packetframe_redirect_watch_unadmitted_links{{module=\"fast-path\"}} {}",
            self.unadmitted
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_and_current_is_healthy() {
        let h = WatchStatus::default().subsystem_health();
        assert_eq!(h.name, "redirect-watch");
        assert_eq!(h.state, HealthState::Healthy);
        let h = WatchStatus {
            overruns: 2,
            resyncs_ok: 1,
            ..WatchStatus::default()
        }
        .subsystem_health();
        assert_eq!(h.state, HealthState::Healthy);
        assert!(h.message.unwrap().contains("2 notification overruns"));
    }

    /// Lost notifications nobody has re-read yet are not "current": a
    /// link created meanwhile is missing from the maps.
    #[test]
    fn an_unrecovered_overrun_degrades_and_says_why_it_persists() {
        let mut s = WatchStatus {
            overruns: 1,
            resync_pending: true,
            ..WatchStatus::default()
        };
        assert_eq!(s.subsystem_health().state, HealthState::Degraded);
        s.last_resync_error = Some("link dump: no reply within 30s".into());
        let m = s.subsystem_health().message.unwrap();
        assert!(m.contains("not recovered yet"), "{m}");
        assert!(m.contains("no reply within 30s"), "{m}");
    }

    /// A watcher that is gone is reported, overrun bookkeeping or not:
    /// nothing follows the link table any more.
    #[test]
    fn a_stopped_watcher_degrades_and_names_the_fallback() {
        let s = WatchStatus {
            stopped: Some("netlink stream closed".into()),
            ..WatchStatus::default()
        };
        let h = s.subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(
            m.contains("netlink stream closed") && m.contains("SIGHUP"),
            "{m}"
        );

        let mut out = String::new();
        s.render_metrics(&mut out);
        assert!(out.contains("packetframe_redirect_watch_running{module=\"fast-path\"} 0"));
    }

    /// Links the maps refused are their own condition: Degraded with or
    /// without an overrun behind it, and named as a capacity problem, not
    /// as lost notifications.
    #[test]
    fn refused_links_degrade_whatever_the_overrun_history() {
        let s = WatchStatus {
            unadmitted: 8,
            ..WatchStatus::default()
        };
        let h = s.subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(
            m.starts_with("8 qualifying links are not in the redirect maps"),
            "{m}"
        );
        assert!(!m.contains("notifications lost"), "{m}");

        let s = WatchStatus {
            overruns: 1,
            resync_pending: true,
            unadmitted: 8,
            ..WatchStatus::default()
        };
        let m = s.subsystem_health().message.unwrap();
        assert!(
            m.contains("notifications lost") && m.contains("8 qualifying links"),
            "{m}"
        );
    }

    #[test]
    fn metrics_render_every_series() {
        let s = WatchStatus {
            overruns: 3,
            resyncs_ok: 2,
            resyncs_failed: 1,
            unadmitted: 4,
            ..WatchStatus::default()
        };
        let mut out = String::new();
        s.render_metrics(&mut out);
        for line in [
            "packetframe_redirect_watch_running{module=\"fast-path\"} 1",
            "packetframe_redirect_watch_overruns_total{module=\"fast-path\"} 3",
            "packetframe_redirect_watch_resyncs_total{module=\"fast-path\",outcome=\"ok\"} 2",
            "packetframe_redirect_watch_resyncs_total{module=\"fast-path\",outcome=\"failed\"} 1",
            "packetframe_redirect_watch_unadmitted_links{module=\"fast-path\"} 4",
        ] {
            assert!(out.lines().any(|l| l == line), "missing {line} in:\n{out}");
        }
    }
}
