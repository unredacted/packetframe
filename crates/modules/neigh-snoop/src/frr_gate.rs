//! The dynamic half of the FRR next-hop gate.
//!
//! The static half is FRR configuration: two prefix-lists that always
//! exist because each holds an operator placeholder `deny` at a low
//! sequence number, and IX route-maps that prefer a route only when its
//! NEXT_HOP is a bilateral peer or in one of those lists, keeping every
//! other route at a local-preference below transit. The failure
//! direction is "demote", never "prefer": a bgpd restart empties the
//! runtime entries and every route-server route drops below transit
//! until they are refilled.
//!
//! This module keeps the runtime entries equal to the set of addresses
//! on the snooped bridges whose kernel neighbour entry resolves, with
//! hysteresis on removal, through `vtysh` and never through the
//! controller upload. Runtime entries carry explicit sequence numbers
//! at or above [`RUNTIME_SEQ_MIN`]; anything below is the operator's and
//! is never touched. Sequence numbers are assigned here rather than left
//! to FRR's auto-numbering, because auto-numbering continues from the
//! placeholder (5, 10, 15, …) and would land runtime entries in the
//! operator's range.
//!
//! The planner is portable and pure: given the desired set and the two
//! parsed lists it returns the commands to run. The Linux runner drives
//! `vtysh`, and a stateful fake `vtysh` script exercises the whole path
//! in the netns tests.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::cfg::GateCfg;
use crate::snapshot::GateOutcome;

/// Runtime entries live at or above this sequence number. Entries below
/// it belong to the operator's static configuration.
pub const RUNTIME_SEQ_MIN: u32 = 100;
const SEQ_STEP: u32 = 5;

/// One `seq N permit|deny PREFIX` line of a prefix-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlEntry {
    pub seq: u32,
    pub permit: bool,
    pub prefix: String,
}

/// A prefix-list as `show ip[v6] prefix-list <name>` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedList {
    /// The list exists in FRR. `false` when vtysh reported it missing —
    /// the static config has not been uploaded, or the name is wrong.
    pub present: bool,
    pub entries: Vec<PlEntry>,
}

impl ParsedList {
    /// The runtime host entries: `permit`, seq ≥ [`RUNTIME_SEQ_MIN`],
    /// `/32` or `/128`. Returns `(address, seq)`.
    pub fn runtime_hosts(&self) -> Vec<(IpAddr, u32)> {
        self.entries
            .iter()
            .filter(|e| e.permit && e.seq >= RUNTIME_SEQ_MIN)
            .filter_map(|e| {
                let (addr, len) = e.prefix.split_once('/')?;
                let ip: IpAddr = addr.parse().ok()?;
                let len: u8 = len.parse().ok()?;
                let host = match ip {
                    IpAddr::V4(_) => len == 32,
                    IpAddr::V6(_) => len == 128,
                };
                host.then_some((ip, e.seq))
            })
            .collect()
    }

    pub fn has_runtime_entries(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.permit && e.seq >= RUNTIME_SEQ_MIN)
    }

    fn next_seq(&self) -> u32 {
        self.entries
            .iter()
            .map(|e| e.seq)
            .filter(|s| *s >= RUNTIME_SEQ_MIN)
            .max()
            .map(|m| m + SEQ_STEP)
            .unwrap_or(RUNTIME_SEQ_MIN)
    }
}

/// Parse `show ip prefix-list <name>` / `show ipv6 prefix-list <name>`
/// text. Tolerates the header line, blank lines and trailing `ge`/`le`
/// qualifiers; a "Can't find" reply means the list does not exist.
pub fn parse_prefix_list(text: &str) -> ParsedList {
    let mut out = ParsedList::default();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('%') {
            // "% Can't find specified prefix-list" and friends.
            return ParsedList::default();
        }
        if t.starts_with("ip prefix-list") || t.starts_with("ipv6 prefix-list") {
            out.present = true;
            continue;
        }
        let mut it = t.split_whitespace();
        if it.next() != Some("seq") {
            continue;
        }
        let Some(seq) = it.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let permit = match it.next() {
            Some("permit") => true,
            Some("deny") => false,
            _ => continue,
        };
        let Some(prefix) = it.next() else {
            continue;
        };
        out.present = true;
        out.entries.push(PlEntry {
            seq,
            permit,
            prefix: prefix.to_string(),
        });
    }
    out
}

/// Removal hysteresis: an address stays desired until it has been
/// unresolved for `remove_after`, so one lost unicast probe cannot flap
/// a prefix between IX and transit.
#[derive(Debug, Default)]
pub struct DesiredTracker {
    last_resolved: HashMap<IpAddr, Instant>,
}

impl DesiredTracker {
    /// Fold in this tick's resolved set and return the desired set.
    pub fn update(
        &mut self,
        resolved_now: &HashSet<IpAddr>,
        now: Instant,
        remove_after: Duration,
    ) -> HashSet<IpAddr> {
        for ip in resolved_now {
            self.last_resolved.insert(*ip, now);
        }
        self.last_resolved
            .retain(|_, t| now.duration_since(*t) <= remove_after);
        self.last_resolved.keys().copied().collect()
    }
}

/// What one reconcile tick decided.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// `configure terminal` body, adds before removes.
    pub commands: Vec<String>,
    pub adds: usize,
    pub removals: usize,
    /// Listed addresses no longer resolved but still inside the
    /// hysteresis window.
    pub pending_removals: usize,
    /// Both lists had lost every runtime entry while the desired set is
    /// non-empty: FRR reloaded, and this plan refills.
    pub reload: bool,
    /// Either list does not exist; nothing can be written.
    pub lists_missing: bool,
}

/// Compute the commands that make the two lists equal to `desired`.
/// `had_runtime_entries` is the previous tick's observation, for reload
/// detection. Pure.
pub fn plan(
    cfg: &GateCfg,
    desired: &HashSet<IpAddr>,
    resolved_now: &HashSet<IpAddr>,
    v4: &ParsedList,
    v6: &ParsedList,
    had_runtime_entries: bool,
) -> Plan {
    let mut out = Plan::default();
    if !v4.present || !v6.present {
        out.lists_missing = true;
        return out;
    }
    let listed_v4: HashMap<IpAddr, u32> = v4.runtime_hosts().into_iter().collect();
    let listed_v6: HashMap<IpAddr, u32> = v6.runtime_hosts().into_iter().collect();
    out.reload = had_runtime_entries
        && !v4.has_runtime_entries()
        && !v6.has_runtime_entries()
        && !desired.is_empty();

    let mut adds_v4: Vec<IpAddr> = Vec::new();
    let mut adds_v6: Vec<IpAddr> = Vec::new();
    for ip in desired {
        match ip {
            IpAddr::V4(_) if !listed_v4.contains_key(ip) => adds_v4.push(*ip),
            IpAddr::V6(v6a) if v6a.is_unicast_link_local() => {} // never a BGP next-hop after prefer-global
            IpAddr::V6(_) if !listed_v6.contains_key(ip) => adds_v6.push(*ip),
            _ => {}
        }
    }
    adds_v4.sort();
    adds_v6.sort();
    let mut removes: Vec<(bool, IpAddr, u32)> = Vec::new();
    for (ip, seq) in &listed_v4 {
        if !desired.contains(ip) {
            removes.push((false, *ip, *seq));
        }
    }
    for (ip, seq) in &listed_v6 {
        if !desired.contains(ip) {
            removes.push((true, *ip, *seq));
        }
    }
    removes.sort_by_key(|(_, ip, _)| *ip);
    out.pending_removals = listed_v4
        .keys()
        .chain(listed_v6.keys())
        .filter(|ip| desired.contains(ip) && !resolved_now.contains(ip))
        .count();

    let mut seq4 = v4.next_seq();
    for ip in &adds_v4 {
        out.commands.push(format!(
            "ip prefix-list {} seq {seq4} permit {ip}/32",
            cfg.v4_list
        ));
        seq4 += SEQ_STEP;
    }
    let mut seq6 = v6.next_seq();
    for ip in &adds_v6 {
        out.commands.push(format!(
            "ipv6 prefix-list {} seq {seq6} permit {ip}/128",
            cfg.v6_list
        ));
        seq6 += SEQ_STEP;
    }
    for (is_v6, ip, seq) in &removes {
        if *is_v6 {
            out.commands.push(format!(
                "no ipv6 prefix-list {} seq {seq} permit {ip}/128",
                cfg.v6_list
            ));
        } else {
            out.commands.push(format!(
                "no ip prefix-list {} seq {seq} permit {ip}/32",
                cfg.v4_list
            ));
        }
    }
    out.adds = adds_v4.len() + adds_v6.len();
    out.removals = removes.len();
    out
}

/// After applying a plan, the lists must hold exactly the desired
/// host addresses (plus the operator's placeholders). `Some(mismatch)`
/// names what differs.
pub fn verify(desired: &HashSet<IpAddr>, v4: &ParsedList, v6: &ParsedList) -> Option<String> {
    let mut actual: HashSet<IpAddr> = v4.runtime_hosts().into_iter().map(|(ip, _)| ip).collect();
    actual.extend(v6.runtime_hosts().into_iter().map(|(ip, _)| ip));
    let want: HashSet<IpAddr> = desired
        .iter()
        .filter(|ip| !matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local()))
        .copied()
        .collect();
    if actual == want {
        return None;
    }
    let missing: Vec<String> = want.difference(&actual).map(|i| i.to_string()).collect();
    let extra: Vec<String> = actual.difference(&want).map(|i| i.to_string()).collect();
    Some(format!(
        "readback mismatch: missing [{}], extra [{}]",
        missing.join(","),
        extra.join(",")
    ))
}

/// The reconciler's state between ticks. Portable so the tick logic is
/// unit-tested with canned vtysh output.
#[derive(Debug, Default)]
pub struct GateState {
    pub tracker: DesiredTracker,
    pub had_runtime_entries: bool,
    pub consecutive_failures: u32,
    pub last_change: Option<Instant>,
    pub outcomes: [u64; GateOutcome::COUNT],
    pub last_error: Option<String>,
    pub permitted_v4: u64,
    pub permitted_v6: u64,
    pub pending_removals: u64,
    pub lists_present: bool,
}

impl GateState {
    pub fn record(&mut self, o: GateOutcome) {
        self.outcomes[o.index()] += 1;
    }
}

#[cfg(target_os = "linux")]
pub use linux::{gate_task, GateInput, RealVtysh, Vtysh};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;

    use tokio::sync::{mpsc, watch};
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, info, warn};

    use crate::engine::EngineMsg;
    use crate::snapshot::GateSnapshot;

    /// `vtysh -c <cmd> [-c <cmd> …]`. One method so a fake is one
    /// method; the real one is a bounded child process.
    pub trait Vtysh: Send + Sync {
        fn run<'a>(
            &'a self,
            commands: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
    }

    /// The real `vtysh`. Path from `PACKETFRAME_VTYSH` (tests point it at
    /// a fake) else `/usr/bin/vtysh`. `kill_on_drop` makes the timeout
    /// mean something: a wedged vtysh is killed, not orphaned.
    pub struct RealVtysh {
        path: PathBuf,
        timeout: Duration,
    }

    impl RealVtysh {
        pub fn from_env(timeout: Duration) -> Self {
            let path = std::env::var_os("PACKETFRAME_VTYSH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/bin/vtysh"));
            Self { path, timeout }
        }

        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Vtysh for RealVtysh {
        fn run<'a>(
            &'a self,
            commands: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
            Box::pin(async move {
                let mut cmd = tokio::process::Command::new(&self.path);
                for c in commands {
                    cmd.arg("-c").arg(c);
                }
                cmd.stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .kill_on_drop(true);
                let child = cmd
                    .spawn()
                    .map_err(|e| format!("spawn {}: {e}", self.path.display()))?;
                let out = tokio::time::timeout(self.timeout, child.wait_with_output())
                    .await
                    .map_err(|_| format!("vtysh timed out after {:?}", self.timeout))?
                    .map_err(|e| format!("vtysh wait: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "vtysh exited {}: {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            })
        }
    }

    /// What the engine publishes to the gate task every housekeeping
    /// tick.
    #[derive(Debug, Clone, Default)]
    pub struct GateInput {
        pub cfg: Option<GateCfg>,
        pub resolved_now: HashSet<IpAddr>,
    }

    fn snapshot_of(state: &GateState, vtysh_ms: u64, now: Instant) -> GateSnapshot {
        GateSnapshot {
            lists_present: state.lists_present,
            permitted_v4: state.permitted_v4,
            permitted_v6: state.permitted_v6,
            pending_removals: state.pending_removals,
            last_change_age_secs: state.last_change.map(|t| now.duration_since(t).as_secs()),
            vtysh_ms,
            last_error: state.last_error.clone(),
            consecutive_failures: state.consecutive_failures,
            outcomes: state.outcomes,
            age_secs: 0,
        }
    }

    async fn show_lists(
        vtysh: &dyn Vtysh,
        cfg: &GateCfg,
    ) -> Result<(ParsedList, ParsedList), String> {
        let v4 = vtysh
            .run(&[format!("show ip prefix-list {}", cfg.v4_list)])
            .await?;
        let v6 = vtysh
            .run(&[format!("show ipv6 prefix-list {}", cfg.v6_list)])
            .await?;
        Ok((parse_prefix_list(&v4), parse_prefix_list(&v6)))
    }

    /// One tick: read, plan, apply, read back. Returns the snapshot.
    async fn tick(
        vtysh: &dyn Vtysh,
        cfg: &GateCfg,
        resolved_now: &HashSet<IpAddr>,
        state: &mut GateState,
    ) -> GateSnapshot {
        let started = Instant::now();
        let desired = state
            .tracker
            .update(resolved_now, started, cfg.remove_after);
        let result: Result<GateOutcome, String> = async {
            let (v4, v6) = show_lists(vtysh, cfg).await?;
            state.lists_present = v4.present && v6.present;
            let p = plan(
                cfg,
                &desired,
                resolved_now,
                &v4,
                &v6,
                state.had_runtime_entries,
            );
            if p.lists_missing {
                return Err("prefix-lists absent; waiting for the static FRR configuration".into());
            }
            state.pending_removals = p.pending_removals as u64;
            if p.commands.is_empty() {
                state.permitted_v4 = v4.runtime_hosts().len() as u64;
                state.permitted_v6 = v6.runtime_hosts().len() as u64;
                state.had_runtime_entries = v4.has_runtime_entries() || v6.has_runtime_entries();
                return Ok(GateOutcome::Noop);
            }
            if p.reload {
                warn!(
                    adds = p.adds,
                    "FRR reload detected: runtime next-hop lists were emptied; refilling"
                );
            }
            let mut body = vec!["configure terminal".to_string()];
            body.extend(p.commands.iter().cloned());
            vtysh.run(&body).await?;
            let (v4b, v6b) = show_lists(vtysh, cfg).await?;
            state.permitted_v4 = v4b.runtime_hosts().len() as u64;
            state.permitted_v6 = v6b.runtime_hosts().len() as u64;
            state.had_runtime_entries = v4b.has_runtime_entries() || v6b.has_runtime_entries();
            if let Some(m) = verify(&desired, &v4b, &v6b) {
                return Err(m);
            }
            info!(
                adds = p.adds,
                removals = p.removals,
                permitted_v4 = state.permitted_v4,
                permitted_v6 = state.permitted_v6,
                "next-hop gate lists reconciled"
            );
            state.last_change = Some(Instant::now());
            Ok(if p.reload {
                GateOutcome::ReloadRefill
            } else {
                GateOutcome::Changed
            })
        }
        .await;
        match result {
            Ok(o) => {
                state.record(o);
                state.consecutive_failures = 0;
                state.last_error = None;
            }
            Err(e) => {
                state.record(GateOutcome::Failed);
                state.consecutive_failures += 1;
                if state.consecutive_failures <= 3 || state.consecutive_failures % 20 == 0 {
                    warn!(error = %e, failures = state.consecutive_failures, "next-hop gate reconcile failed");
                } else {
                    debug!(error = %e, "next-hop gate reconcile failed");
                }
                state.last_error = Some(e);
            }
        }
        snapshot_of(state, started.elapsed().as_millis() as u64, Instant::now())
    }

    /// The reconcile loop: one tick per `interval`, snapshot back to the
    /// engine after each. Stops when the gate is unconfigured or on
    /// cancel.
    pub async fn gate_task(
        vtysh: Arc<dyn Vtysh>,
        mut input: watch::Receiver<GateInput>,
        ctl: mpsc::UnboundedSender<EngineMsg>,
        cancel: CancellationToken,
    ) {
        let mut state = GateState::default();
        loop {
            let inp = input.borrow_and_update().clone();
            let Some(cfg) = inp.cfg.clone() else {
                // Not configured: wait for a change or cancel.
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = input.changed() => { if r.is_err() { return; } continue; }
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(cfg.interval) => {}
            }
            let inp = input.borrow_and_update().clone();
            let Some(cfg) = inp.cfg.clone() else {
                continue;
            };
            let snap = tick(vtysh.as_ref(), &cfg, &inp.resolved_now, &mut state).await;
            if ctl.send(EngineMsg::Gate(snap)).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GateCfg {
        GateCfg {
            v4_list: "GATE4".into(),
            v6_list: "GATE6".into(),
            interval: Duration::from_secs(30),
            remove_after: Duration::from_secs(180),
        }
    }

    const V4_TEXT: &str = "ip prefix-list GATE4: 3 entries\n   seq 5 deny 0.0.0.0/32\n   seq 100 permit 192.0.2.10/32\n   seq 105 permit 192.0.2.11/32\n";
    const V6_TEXT: &str = "ipv6 prefix-list GATE6: 2 entries\n   seq 5 deny ::/128\n   seq 100 permit 2001:db8::10/128\n";

    fn set(v: &[&str]) -> HashSet<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn parses_text_and_classifies_runtime_entries() {
        let v4 = parse_prefix_list(V4_TEXT);
        assert!(v4.present);
        assert_eq!(v4.entries.len(), 3);
        let hosts = v4.runtime_hosts();
        assert_eq!(
            hosts.len(),
            2,
            "the seq-5 placeholder is not a runtime entry"
        );
        assert_eq!(hosts[0], ("192.0.2.10".parse().unwrap(), 100));
        assert!(v4.has_runtime_entries());
        assert_eq!(v4.next_seq(), 110);

        let missing = parse_prefix_list("% Can't find specified prefix-list\n");
        assert!(!missing.present);
        let empty = parse_prefix_list("");
        assert!(!empty.present);
        let placeholders =
            parse_prefix_list("ip prefix-list GATE4: 1 entries\n   seq 5 deny 0.0.0.0/32\n");
        assert!(placeholders.present && !placeholders.has_runtime_entries());
        assert_eq!(placeholders.next_seq(), RUNTIME_SEQ_MIN);
        // Trailing qualifiers and non-host prefixes are tolerated but not hosts.
        let odd =
            parse_prefix_list("ip prefix-list X: 1 entries\n   seq 200 permit 10.0.0.0/8 le 24\n");
        assert!(odd.runtime_hosts().is_empty());
    }

    #[test]
    fn plan_adds_before_removes_with_explicit_sequences() {
        let v4 = parse_prefix_list(V4_TEXT);
        let v6 = parse_prefix_list(V6_TEXT);
        // .10 stays, .11 leaves, .12 arrives; v6 ::20 arrives; link-local never listed.
        let desired = set(&[
            "192.0.2.10",
            "192.0.2.12",
            "2001:db8::10",
            "2001:db8::20",
            "fe80::1",
        ]);
        let p = plan(&cfg(), &desired, &desired, &v4, &v6, true);
        assert!(!p.reload && !p.lists_missing);
        assert_eq!(p.adds, 2);
        assert_eq!(p.removals, 1);
        assert_eq!(
            p.commands,
            vec![
                "ip prefix-list GATE4 seq 110 permit 192.0.2.12/32",
                "ipv6 prefix-list GATE6 seq 105 permit 2001:db8::20/128",
                "no ip prefix-list GATE4 seq 105 permit 192.0.2.11/32",
            ]
        );
    }

    #[test]
    fn plan_is_empty_when_lists_match_and_never_touches_placeholders() {
        let v4 = parse_prefix_list(V4_TEXT);
        let v6 = parse_prefix_list(V6_TEXT);
        let desired = set(&["192.0.2.10", "192.0.2.11", "2001:db8::10"]);
        let p = plan(&cfg(), &desired, &desired, &v4, &v6, true);
        assert!(p.commands.is_empty());
        assert_eq!(p.pending_removals, 0);
        assert!(verify(&desired, &v4, &v6).is_none());
        // With nothing desired, only the runtime entries go; seq 5 stays.
        let p = plan(&cfg(), &HashSet::new(), &HashSet::new(), &v4, &v6, true);
        assert_eq!(p.removals, 3);
        assert!(p
            .commands
            .iter()
            .all(|c| c.starts_with("no ") && !c.contains("seq 5 ")));
    }

    #[test]
    fn hysteresis_delays_removal_and_reports_pending() {
        let mut t = DesiredTracker::default();
        let t0 = Instant::now();
        let ra = Duration::from_secs(180);
        let both = set(&["192.0.2.10", "192.0.2.11", "2001:db8::10"]);
        assert_eq!(t.update(&both, t0, ra), both);
        let only10 = set(&["192.0.2.10", "2001:db8::10"]);
        // .11 unresolved but inside the window: still desired.
        let d = t.update(&only10, t0 + Duration::from_secs(60), ra);
        assert_eq!(d, both);
        let v4 = parse_prefix_list(V4_TEXT);
        let v6 = parse_prefix_list(V6_TEXT);
        let p = plan(&cfg(), &d, &only10, &v4, &v6, true);
        assert_eq!(p.pending_removals, 1);
        assert_eq!(p.removals, 0, "not yet");
        // Past the window: gone.
        let d = t.update(&only10, t0 + Duration::from_secs(181), ra);
        assert_eq!(d, only10);
        let p = plan(&cfg(), &d, &only10, &v4, &v6, true);
        assert_eq!(p.removals, 1);
        assert_eq!(p.pending_removals, 0);
    }

    #[test]
    fn reload_is_detected_and_refilled() {
        let placeholders4 =
            parse_prefix_list("ip prefix-list GATE4: 1 entries\n   seq 5 deny 0.0.0.0/32\n");
        let placeholders6 =
            parse_prefix_list("ipv6 prefix-list GATE6: 1 entries\n   seq 5 deny ::/128\n");
        let desired = set(&["192.0.2.10", "2001:db8::10"]);
        let p = plan(
            &cfg(),
            &desired,
            &desired,
            &placeholders4,
            &placeholders6,
            true,
        );
        assert!(p.reload);
        assert_eq!(p.adds, 2);
        assert_eq!(
            p.commands[0],
            "ip prefix-list GATE4 seq 100 permit 192.0.2.10/32"
        );
        // First start over empty lists is not a reload.
        let p = plan(
            &cfg(),
            &desired,
            &desired,
            &placeholders4,
            &placeholders6,
            false,
        );
        assert!(!p.reload);
        assert_eq!(p.adds, 2);
    }

    #[test]
    fn missing_lists_produce_no_commands() {
        let p = plan(
            &cfg(),
            &set(&["192.0.2.10"]),
            &set(&["192.0.2.10"]),
            &parse_prefix_list("% Can't find specified prefix-list"),
            &parse_prefix_list(V6_TEXT),
            false,
        );
        assert!(p.lists_missing);
        assert!(p.commands.is_empty());
    }

    #[test]
    fn verify_names_the_difference() {
        let v4 = parse_prefix_list(V4_TEXT);
        let v6 = parse_prefix_list(V6_TEXT);
        let want = set(&["192.0.2.10", "2001:db8::10", "192.0.2.99"]);
        let m = verify(&want, &v4, &v6).unwrap();
        assert!(m.contains("missing [192.0.2.99]"), "{m}");
        assert!(m.contains("extra [192.0.2.11]"), "{m}");
    }
}
