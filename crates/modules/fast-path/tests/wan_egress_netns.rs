//! Integration coverage for `wan_egress` against a real kernel.
//!
//! The planner and diff are unit-tested; what only a live kernel can
//! prove is that the rules they produce do what the design says to the
//! kernel's own route lookup:
//!
//! 1. After a reconcile, a wan-egress source's traffic to a destination
//!    `main` routes via the "IX" interface resolves via the "WAN" table
//!    instead, a kept destination still resolves via `main`, and a
//!    source outside the directive is unaffected.
//! 2. The goto needs its anchor: removing the anchor externally puts
//!    the source back in `main` (an unresolved goto is skipped), and
//!    the next reconcile repairs it, as it does a removed goto.
//! 3. A converged reconcile emits no `RTNLGRP_IPV4_RULE` notification.
//! 4. Removal takes out every owned rule, anchor included, and no
//!    foreign rule, including the one parked at `main - 1`.
//! 5. With no unconditional `lookup main`, or with two of them, nothing
//!    is written.
//! 6. The reconcile thread repairs a removed rule on its own, prompted
//!    by the rule event rather than the 30 s tick.
//! 7. Stopping the reconciler without removal (the breaker-trip and
//!    `detach --keep-vpp` paths) leaves working rules, and a new
//!    reconciler adopts them without writing anything.
//! 8. Every rule names a table or a goto (UniFi's udapi-server refuses
//!    to start otherwise), and the `nop` anchor an older daemon left is
//!    replaced by the `lookup local` one without the goto losing its
//!    target.
//!
//! The topology mirrors the platform shape the feature exists for:
//! `main` moved from 32766 to 32000 and holding a specific route via
//! the IX interface, the WAN table (201) with a default via the WAN
//! interface, and a catch-all `lookup 201` after `main`. Each test runs
//! in its own netns; utilities are copied from `anyip_netns.rs`, since
//! each `tests/*.rs` is its own crate.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::{Duration, Instant};

use futures::TryStreamExt;
use netlink_packet_route::rule::RuleAttribute;
use packetframe_common::config::Config;
use packetframe_fast_path::wan_egress::{
    reconcile_once, remove_all_owned, spec_from_directives, Condition, Layout, OwnedRule,
    PlanError, WanEgress, WanEgressSpec,
};
use packetframe_fast_path::PACKETFRAME_RT_PROTOCOL;

struct Names {
    netns: String,
    lan: String,
    lan_peer: String,
    ix: String,
    ix_peer: String,
    wan: String,
    wan_peer: String,
}

impl Names {
    fn new(tag: &str) -> Self {
        // PID suffix separates parallel test binaries; the tag
        // separates the `#[test]` fns inside this one.
        let s = format!("{tag}{:x}", std::process::id() & 0xffff);
        Names {
            netns: format!("pfwe{s}"),
            lan: format!("wl{s}"),
            lan_peer: format!("wL{s}"),
            ix: format!("wi{s}"),
            ix_peer: format!("wI{s}"),
            wan: format!("ww{s}"),
            wan_peer: format!("wW{s}"),
        }
    }
}

struct NetnsGuard {
    name: String,
}

impl NetnsGuard {
    fn setup(n: &Names) -> Self {
        let _ = Command::new("ip").args(["netns", "del", &n.netns]).status();
        run(&["ip", "netns", "add", &n.netns]);
        let ns = |args: &[&str]| ns_run(&n.netns, args);
        ns(&["ip", "link", "set", "lo", "up"]);
        for (a, b) in [
            (&n.lan, &n.lan_peer),
            (&n.ix, &n.ix_peer),
            (&n.wan, &n.wan_peer),
        ] {
            run(&[
                "ip", "link", "add", a, "netns", &n.netns, "type", "veth", "peer", "name", b,
                "netns", &n.netns,
            ]);
            ns(&["ip", "link", "set", a, "up"]);
            ns(&["ip", "link", "set", b, "up"]);
        }
        // `route get ... iif` is an input lookup: forwarding on, and no
        // reverse-path check to trip over the synthetic sources.
        for key in [
            "net.ipv4.ip_forward=1",
            "net.ipv4.conf.all.rp_filter=0",
            "net.ipv4.conf.default.rp_filter=0",
        ] {
            ns(&["sysctl", "-qw", key]);
        }
        ns(&[
            "sysctl",
            "-qw",
            &format!("net.ipv4.conf.{}.rp_filter=0", n.lan),
        ]);
        ns(&["ip", "addr", "add", "198.18.0.1/24", "dev", &n.lan]);
        ns(&["ip", "addr", "add", "198.51.100.1/30", "dev", &n.ix]);
        ns(&["ip", "addr", "add", "203.0.113.1/30", "dev", &n.wan]);
        // `main`: the "BGP" route via the IX, and a kept destination
        // that is also reached that way.
        ns(&[
            "ip",
            "route",
            "add",
            "198.51.100.128/25",
            "via",
            "198.51.100.2",
            "dev",
            &n.ix,
        ]);
        ns(&[
            "ip",
            "route",
            "add",
            "192.0.2.0/24",
            "via",
            "198.51.100.2",
            "dev",
            &n.ix,
        ]);
        // The WAN table.
        ns(&[
            "ip",
            "route",
            "add",
            "default",
            "via",
            "203.0.113.2",
            "dev",
            &n.wan,
            "table",
            "201",
        ]);
        // Move main, as the platform does, and put the WAN catch-all
        // after it. A foreign rule parks at main-1 so the planner has
        // to step around it.
        ns(&["ip", "rule", "del", "pref", "32766", "lookup", "main"]);
        ns(&["ip", "rule", "add", "pref", "32000", "lookup", "main"]);
        ns(&["ip", "rule", "add", "pref", "32766", "lookup", "201"]);
        ns(&[
            "ip",
            "rule",
            "add",
            "pref",
            "31999",
            "from",
            "203.0.113.200",
            "lookup",
            "201",
        ]);
        NetnsGuard {
            name: n.netns.clone(),
        }
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}

fn run(args: &[&str]) {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    assert!(status.success(), "command failed: {args:?}");
}

fn ns_run(netns: &str, args: &[&str]) {
    let mut full = vec!["netns", "exec", netns];
    full.extend_from_slice(args);
    let status = Command::new("ip")
        .args(&full)
        .status()
        .unwrap_or_else(|e| panic!("spawn ip {full:?}: {e}"));
    assert!(status.success(), "command failed: ip {full:?}");
}

fn ns_output(netns: &str, args: &[&str]) -> String {
    let mut full = vec!["netns", "exec", netns];
    full.extend_from_slice(args);
    let out = Command::new("ip")
        .args(&full)
        .output()
        .unwrap_or_else(|e| panic!("spawn ip {full:?}: {e}"));
    assert!(
        out.status.success(),
        "command failed: ip {full:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Move this thread (and every thread and runtime it creates
/// afterwards) into the netns.
fn enter_netns(name: &str) -> File {
    let path = format!("/run/netns/{name}");
    let f = File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let rc = unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(
        rc,
        0,
        "setns({path}) failed: {}",
        std::io::Error::last_os_error()
    );
    f
}

/// The egress device the kernel picks for a forwarded packet.
fn egress(n: &Names, dst: &str, src: &str) -> String {
    let out = ns_output(
        &n.netns,
        &["ip", "-4", "route", "get", dst, "from", src, "iif", &n.lan],
    );
    let mut words = out.split_whitespace();
    while let Some(w) = words.next() {
        if w == "dev" {
            return words.next().unwrap_or_default().to_string();
        }
    }
    panic!("no `dev` in `ip route get {dst} from {src}`: {out}");
}

const SRC: &str = "198.18.0.10";
/// Inside the LAN subnet but outside the directive.
const OTHER_SRC: &str = "198.18.0.200";
const VIA_IX: &str = "198.51.100.130";
const KEPT: &str = "192.0.2.10";

fn spec() -> WanEgressSpec {
    let cfg =
        Config::parse("module fast-path\n  wan-egress from 198.18.0.0/25 keep 192.0.2.0/24\n")
            .expect("config");
    spec_from_directives(&cfg.modules[0].directives).expect("a wan-egress spec")
}

fn rules_text(n: &Names) -> String {
    ns_output(&n.netns, &["ip", "-4", "rule", "show"])
}

/// The check UniFi's udapi-server makes at start, which aborts it on a
/// rule with neither a table nor a goto.
fn assert_every_rule_has_a_table_or_goto(n: &Names) {
    let text = rules_text(n);
    for line in text.lines() {
        assert!(
            line.contains("lookup") || line.contains("goto"),
            "`{line}` has neither a table nor a goto:\n{text}"
        );
    }
}

/// Owned rules, counted from a netlink dump (iproute2's rendering of a
/// rule's protocol differs across versions).
async fn owned_count() -> usize {
    let (conn, handle, _) = rtnetlink::new_connection().expect("netlink");
    tokio::spawn(conn);
    let mut rules = handle.rule().get(rtnetlink::IpVersion::V4).execute();
    let mut n = 0;
    while let Some(m) = rules.try_next().await.expect("rule dump") {
        if m.attributes.iter().any(
            |a| matches!(a, RuleAttribute::Protocol(p) if u8::from(*p) == PACKETFRAME_RT_PROTOCOL),
        ) {
            n += 1;
        }
    }
    n
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime")
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn wan_egress_steers_repairs_stays_quiet_and_detaches() {
    let n = Names::new("a");
    let _guard = NetnsGuard::setup(&n);
    let _ns = enter_netns(&n.netns);
    let rt = runtime();
    let spec = spec();

    assert_eq!(egress(&n, VIA_IX, SRC), n.ix, "baseline: main wins");

    // 1. First reconcile installs everything, stepping around the
    // foreign rule at main-1.
    let report = rt.block_on(reconcile_once(&spec)).expect("reconcile");
    assert!(report.converged(), "{report:?}");
    assert_eq!(
        report.layout,
        Ok(Layout {
            main: 32000,
            keep: 31997,
            goto: 31998,
            target: 32001,
            anchor: true,
        })
    );
    // 5 default keeps + 192.0.2.0/24, one goto, one anchor.
    assert_eq!(report.desired, 8);
    assert_eq!(report.added.len(), 8);
    assert_eq!(rt.block_on(owned_count()), 8);

    assert_eq!(egress(&n, VIA_IX, SRC), n.wan, "source skips main");
    assert_eq!(
        egress(&n, KEPT, SRC),
        n.ix,
        "kept destination stays in main"
    );
    assert_eq!(
        egress(&n, VIA_IX, OTHER_SRC),
        n.ix,
        "other sources untouched"
    );
    let text = rules_text(&n);
    assert!(text.contains("32001:\tfrom all lookup local"), "{text}");
    assert_every_rule_has_a_table_or_goto(&n);

    // 2. The anchor is load-bearing, and repaired.
    ns_run(&n.netns, &["ip", "rule", "del", "pref", "32001"]);
    assert_eq!(
        egress(&n, VIA_IX, SRC),
        n.ix,
        "an unresolved goto is skipped, putting the source back in main"
    );
    let report = rt.block_on(reconcile_once(&spec)).expect("repair anchor");
    assert_eq!(report.added.len(), 1, "{report:?}");
    assert!(report.removed.is_empty(), "{report:?}");
    assert_eq!(egress(&n, VIA_IX, SRC), n.wan);

    // ... and so is a goto.
    ns_run(
        &n.netns,
        &[
            "ip",
            "rule",
            "del",
            "pref",
            "31998",
            "from",
            "198.18.0.0/25",
            "goto",
            "32001",
        ],
    );
    assert_eq!(egress(&n, VIA_IX, SRC), n.ix);
    let report = rt.block_on(reconcile_once(&spec)).expect("repair goto");
    assert_eq!(report.added.len(), 1, "{report:?}");
    assert_eq!(egress(&n, VIA_IX, SRC), n.wan);

    // 3. Converged: a pass (a later daemon's adoption looks exactly
    // like this) writes nothing, so rule subscribers hear nothing.
    rt.block_on(async {
        let (conn, _handle, mut msgs) =
            rtnetlink::new_multicast_connection(&[rtnetlink::MulticastGroup::Ipv4Rule])
                .expect("subscribe RTNLGRP_IPV4_RULE");
        tokio::spawn(conn);
        let report = reconcile_once(&spec).await.expect("quiet reconcile");
        assert!(report.converged() && !report.wrote(), "{report:?}");
        assert_eq!(report.present, 8);
        let quiet = tokio::time::timeout(
            Duration::from_millis(500),
            futures::StreamExt::next(&mut msgs),
        )
        .await;
        if let Ok(Some((msg, _))) = quiet {
            panic!("converged reconcile emitted a rule notification: {msg:?}");
        }
    });

    // 4. Removal: every owned rule, no foreign one.
    let removed = rt.block_on(remove_all_owned()).expect("remove");
    assert_eq!(removed, 8);
    assert_eq!(rt.block_on(owned_count()), 0);
    let text = rules_text(&n);
    for foreign in [
        "31999:\tfrom 203.0.113.200 lookup 201",
        "32000:\tfrom all lookup main",
        "32766:\tfrom all lookup 201",
    ] {
        assert!(
            text.contains(foreign),
            "foreign rule `{foreign}` gone:\n{text}"
        );
    }
    assert_eq!(
        egress(&n, VIA_IX, SRC),
        n.ix,
        "back to the platform's behaviour"
    );
    assert_eq!(
        rt.block_on(remove_all_owned()).expect("second remove"),
        0,
        "a second removal is a no-op, not an error"
    );
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn wan_egress_without_main_writes_nothing() {
    let n = Names::new("b");
    let _guard = NetnsGuard::setup(&n);
    let _ns = enter_netns(&n.netns);
    let rt = runtime();

    // Two unconditional `lookup main` rules: skipping the first would
    // land on the second, so nothing is written.
    ns_run(
        &n.netns,
        &["ip", "rule", "add", "pref", "32100", "lookup", "main"],
    );
    let before = rules_text(&n);
    let report = rt.block_on(reconcile_once(&spec())).expect("reconcile");
    assert!(
        matches!(
            report.layout,
            Err(PlanError::SecondMain {
                first: 32000,
                second: 32100
            })
        ),
        "{report:?}"
    );
    assert!(!report.wrote(), "{report:?}");
    assert_eq!(rules_text(&n), before);

    // No `lookup main` at all.
    ns_run(
        &n.netns,
        &["ip", "rule", "del", "pref", "32100", "lookup", "main"],
    );
    ns_run(
        &n.netns,
        &["ip", "rule", "del", "pref", "32000", "lookup", "main"],
    );
    let before = rules_text(&n);
    let report = rt.block_on(reconcile_once(&spec())).expect("reconcile");
    assert!(report.layout.is_err(), "{report:?}");
    assert!(!report.wrote(), "{report:?}");
    assert_eq!(rules_text(&n), before);
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn wan_egress_thread_repairs_on_the_rule_event() {
    let n = Names::new("c");
    let _guard = NetnsGuard::setup(&n);
    let _ns = enter_netns(&n.netns);
    let rt = runtime();

    // Spawned after setns, so its thread and sockets live in the netns.
    let w = WanEgress::start(spec()).expect("start");
    let status = w.status();
    assert_eq!(status.condition, Condition::Converged, "{status:?}");
    assert_eq!((status.present, status.desired), (Some(8), 8));
    assert_eq!(egress(&n, VIA_IX, SRC), n.wan);

    ns_run(&n.netns, &["ip", "rule", "del", "pref", "32001"]);
    // The tick is 30 s; the event path answers within its 1 s debounce.
    let deadline = Instant::now() + Duration::from_secs(10);
    while egress(&n, VIA_IX, SRC) != n.wan {
        assert!(
            Instant::now() < deadline,
            "the removed anchor was not put back:\n{}",
            rules_text(&n)
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // A breaker trip or `detach --keep-vpp`: the reconciler stops and
    // the rules stay, still steering the sources to the WAN.
    w.stop();
    assert_eq!(rt.block_on(owned_count()), 8);
    assert_eq!(egress(&n, VIA_IX, SRC), n.wan, "kept rules keep working");

    // The next daemon adopts them: its first pass finds everything in
    // place and writes nothing, so no rule event is emitted.
    let w = rt.block_on(async {
        let (conn, _handle, mut msgs) =
            rtnetlink::new_multicast_connection(&[rtnetlink::MulticastGroup::Ipv4Rule])
                .expect("subscribe RTNLGRP_IPV4_RULE");
        tokio::spawn(conn);
        // `start` builds its own runtime, so it must run off this one.
        let w = tokio::task::spawn_blocking(|| WanEgress::start(spec()))
            .await
            .expect("join")
            .expect("adopting start");
        let quiet = tokio::time::timeout(
            Duration::from_millis(500),
            futures::StreamExt::next(&mut msgs),
        )
        .await;
        if let Ok(Some((msg, _))) = quiet {
            panic!("adoption emitted a rule notification: {msg:?}");
        }
        w
    });
    let status = w.status();
    assert_eq!(status.condition, Condition::Converged, "{status:?}");
    assert_eq!(status.present, Some(8));

    // The directive leaves the config (the reload path): retire removes
    // every rule and says so before the reconciler is dropped.
    assert_eq!(w.retire().expect("retire"), 8);
    assert_eq!(w.status().condition, Condition::Retired);
    assert_eq!(w.spec(), None);
    w.stop();
    assert_eq!(rt.block_on(owned_count()), 0);
    assert_eq!(egress(&n, VIA_IX, SRC), n.ix);
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn wan_egress_replaces_a_legacy_nop_anchor() {
    let n = Names::new("d");
    let _guard = NetnsGuard::setup(&n);
    let _ns = enter_netns(&n.netns);
    let rt = runtime();
    let spec = spec();

    // What a daemon from before the `lookup local` anchor left behind:
    // the same keep and goto rules, the anchor as a tagged `nop`.
    let report = rt.block_on(reconcile_once(&spec)).expect("reconcile");
    assert!(report.converged(), "{report:?}");
    ns_run(&n.netns, &["ip", "rule", "del", "pref", "32001"]);
    ns_run(
        &n.netns,
        &[
            "ip", "rule", "add", "pref", "32001", "nop", "protocol", "199",
        ],
    );
    assert_eq!(rt.block_on(owned_count()), 8);
    assert_eq!(egress(&n, VIA_IX, SRC), n.wan, "the old anchor is a target");

    // One pass adds the new anchor, then removes the old one. Deleting
    // the first of two rules at 32001 moves the goto to the second; if
    // it did not, the goto would sit there unresolved and, matching the
    // desired set, never be rewritten.
    let report = rt.block_on(reconcile_once(&spec)).expect("replace anchor");
    assert!(report.converged(), "{report:?}");
    assert_eq!(report.added, vec![OwnedRule::Anchor { priority: 32001 }]);
    assert_eq!(report.removed, vec!["32001: from all nop (legacy anchor)"]);
    assert_eq!(egress(&n, VIA_IX, SRC), n.wan, "the goto kept its target");
    assert_eq!(egress(&n, KEPT, SRC), n.ix);
    assert_eq!(rt.block_on(owned_count()), 8);
    assert_every_rule_has_a_table_or_goto(&n);

    let report = rt.block_on(reconcile_once(&spec)).expect("quiet pass");
    assert!(report.converged() && !report.wrote(), "{report:?}");
}
