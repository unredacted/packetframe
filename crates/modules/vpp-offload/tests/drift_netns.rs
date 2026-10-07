//! The exemption-drift scan against a real kernel.
//!
//! The comparison is unit-tested; what only a live kernel can prove is
//! how it answers the dump the scan sends:
//!
//! 1. A strict dump of the tables the policy rules select returns the
//!    routes in them and nothing from a table no rule names, and a rule
//!    naming a table no route has created (every box's `lookup default`)
//!    does not fail it — the kernel reports that as ENOENT in the DONE
//!    message.
//! 2. With the selection unknown, every table is dumped.
//! 3. The same for IPv6.
//! 4. An interrupt between chunks abandons the dump.
//! 5. The link watch names an up/down transition once, and ignores a
//!    promiscuity toggle and a device created down.
//! 6. End to end, the findings name the tunnel paths in selected tables
//!    only, for both families.
//!
//! Each test runs in its own netns on its own thread: a dummy `pfm0`
//! stands in for a VPP member port, a dummy `pft0` for a tunnel VPP
//! cannot take. Needs root (`unshare`, `ip`).

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use netlink_packet_route::AddressFamily;
use packetframe_vpp_offload::drift::{
    dump_routes, dump_routes_v6, dump_rule_tables, DriftScope, DriftWatch, KernelDriftWatch,
    KernelLinkWatch, ScanError, V6Drift, VppReach,
};

fn ip(args: &[&str]) {
    let st = std::process::Command::new("ip")
        .args(args)
        .status()
        .expect("spawn ip");
    assert!(st.success(), "ip {args:?}");
}

/// Run `f` on a fresh thread in a fresh netns holding the fixture
/// topology. `ip` children inherit the thread's namespace.
fn in_netns(f: impl FnOnce() + Send + 'static) {
    std::thread::spawn(move || {
        // SAFETY: unshare affects only this thread's namespaces.
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        assert_eq!(rc, 0, "unshare: {}", std::io::Error::last_os_error());
        ip(&["link", "set", "lo", "up"]);
        for dev in ["pfm0", "pft0"] {
            ip(&["link", "add", dev, "type", "dummy"]);
            ip(&["link", "set", dev, "up"]);
        }
        ip(&["addr", "add", "192.0.2.1/26", "dev", "pfm0"]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:ff::1/64",
            "dev",
            "pfm0",
            "nodad",
        ]);
        // The bulk's shape (via a gateway on a member: cleared) and a
        // tunnel path (a finding), in main.
        ip(&[
            "route",
            "add",
            "203.0.113.0/24",
            "via",
            "192.0.2.2",
            "dev",
            "pfm0",
        ]);
        ip(&["route", "add", "198.51.100.0/24", "dev", "pft0"]);
        ip(&["-6", "route", "add", "2001:db8:1::/48", "dev", "pft0"]);
        // Table 100, selected by a rule; table 200, named by none.
        for family in ["-4", "-6"] {
            for table in ["100", "300"] {
                // 300: a rule for a table no route creates.
                ip(&[
                    family, "rule", "add", "from", "all", "lookup", table, "pref", table,
                ]);
            }
        }
        ip(&[
            "route",
            "add",
            "192.0.2.128/26",
            "dev",
            "pft0",
            "table",
            "100",
        ]);
        ip(&[
            "route",
            "add",
            "192.0.2.192/26",
            "dev",
            "pft0",
            "table",
            "200",
        ]);
        ip(&[
            "-6",
            "route",
            "add",
            "2001:db8:2::/48",
            "dev",
            "pft0",
            "table",
            "100",
        ]);
        ip(&[
            "-6",
            "route",
            "add",
            "2001:db8:3::/48",
            "dev",
            "pft0",
            "table",
            "200",
        ]);
        f();
    })
    .join()
    .expect("netns test thread");
}

fn reach() -> VppReach {
    VppReach {
        members: vec!["pfm0".into()],
        ..VppReach::default()
    }
}

fn never() -> impl FnMut() -> Option<String> {
    || None
}

#[test]
#[ignore = "needs root: unshare(CLONE_NEWNET) and ip"]
fn a_strict_dump_reads_only_the_tables_rules_select() {
    in_netns(|| {
        let tables = dump_rule_tables(AddressFamily::Inet)
            .expect("rules readable")
            .expect("rules name tables");
        for t in [255, 254, 253, 100, 300] {
            assert!(tables.contains(&t), "table {t} is selected: {tables:?}");
        }
        assert!(!tables.contains(&200), "{tables:?}");

        // 253 and 300 exist only as rules; the dump must not fail on them.
        let dump = dump_routes(&reach(), Some(&tables), &mut never()).expect("dump");
        let kept: Vec<(String, u32)> = dump
            .routes
            .iter()
            .filter(|r| r.oifs == ["pft0"])
            .map(|r| {
                (
                    format!("{}/{}", r.prefix.addr, r.prefix.prefix_len),
                    r.table,
                )
            })
            .collect();
        assert!(kept.contains(&("198.51.100.0/24".into(), 254)), "{kept:?}");
        assert!(kept.contains(&("192.0.2.128/26".into(), 100)), "{kept:?}");
        assert!(
            !dump.routes.iter().any(|r| r.table == 200),
            "table 200 is named by no rule and must not be dumped: {:?}",
            dump.routes
        );
        assert!(
            !dump
                .routes
                .iter()
                .any(|r| r.prefix.addr == std::net::Ipv4Addr::new(203, 0, 113, 0)),
            "the member-gatewayed route is read and discarded"
        );
        assert!(
            dump.read > dump.routes.len(),
            "read counts what was discarded too"
        );

        // Unknown selection: every table, 200 included.
        let all = dump_routes(&reach(), None, &mut never()).expect("dump");
        assert!(
            all.routes
                .iter()
                .any(|r| r.table == 200 && r.prefix.prefix_len == 26),
            "{:?}",
            all.routes
        );
    });
}

#[test]
#[ignore = "needs root: unshare(CLONE_NEWNET) and ip"]
fn a_strict_v6_dump_reads_only_the_tables_rules_select() {
    in_netns(|| {
        let tables = dump_rule_tables(AddressFamily::Inet6)
            .expect("rules readable")
            .expect("rules name tables");
        assert!(tables.contains(&100) && tables.contains(&300), "{tables:?}");
        assert!(!tables.contains(&200), "{tables:?}");

        let dump = dump_routes_v6(&reach(), Some(&tables), &mut never()).expect("dump");
        let kept: Vec<(String, u32)> = dump
            .routes
            .iter()
            .map(|r| {
                (
                    format!("{}/{}", r.prefix.addr, r.prefix.prefix_len),
                    r.table,
                )
            })
            .collect();
        assert!(kept.contains(&("2001:db8:1::/48".into(), 254)), "{kept:?}");
        assert!(kept.contains(&("2001:db8:2::/48".into(), 100)), "{kept:?}");
        assert!(!dump.routes.iter().any(|r| r.table == 200), "{kept:?}");

        let all = dump_routes_v6(&reach(), None, &mut never()).expect("dump");
        assert!(
            all.routes.iter().any(|r| r.table == 200),
            "{:?}",
            all.routes
        );
    });
}

#[test]
#[ignore = "needs root: unshare(CLONE_NEWNET) and ip"]
fn an_interrupt_abandons_the_dump() {
    in_netns(|| {
        let got = dump_routes(&reach(), None, &mut || Some("pft0 down".into()));
        assert!(
            matches!(&got, Err(ScanError::Interrupted(w)) if w == "pft0 down"),
            "{got:?}"
        );
    });
}

/// Linkwatch delivers operstate changes asynchronously, within a second
/// (`linkwatch_fire_event`), so a watch is asked only once they settle.
fn settled(links: &mut KernelLinkWatch) -> Vec<String> {
    let mut seen = Vec::new();
    let mut quiet_since = Instant::now();
    while quiet_since.elapsed() < Duration::from_millis(1500) {
        if let Some(c) = links.changed() {
            seen.push(c);
            quiet_since = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    seen
}

#[test]
#[ignore = "needs root: unshare(CLONE_NEWNET) and ip"]
fn the_link_watch_names_up_and_down_and_nothing_else() {
    in_netns(|| {
        let mut links = KernelLinkWatch::open().expect("link watch");
        // The fixture's own bring-up may still be settling.
        let _ = settled(&mut links);

        ip(&["link", "set", "pft0", "promisc", "on"]);
        ip(&["link", "add", "pfn0", "type", "dummy"]);
        assert_eq!(
            settled(&mut links),
            Vec::<String>::new(),
            "promiscuity and a device created down move no routes"
        );

        ip(&["link", "set", "pft0", "down"]);
        let seen = settled(&mut links);
        assert!(
            seen.last().is_some_and(|c| c == "pft0 down"),
            "a link going down is named: {seen:?}"
        );

        ip(&["link", "set", "pfn0", "up"]);
        let seen = settled(&mut links);
        assert!(
            seen.iter().any(|c| c.starts_with("pfn0 up")),
            "a link coming up is named: {seen:?}"
        );

        // Unregistering closes the device first, so the kernel says "down"
        // before it says "deleted"; either names the change, once.
        ip(&["link", "del", "pfn0"]);
        let seen = settled(&mut links);
        assert!(
            matches!(seen.as_slice(), [c] if c == "pfn0 down" || c == "pfn0 removed"),
            "an up device deleted is named once: {seen:?}"
        );
    });
}

#[test]
#[ignore = "needs root: unshare(CLONE_NEWNET) and ip"]
fn the_scan_names_tunnel_paths_in_selected_tables_only() {
    in_netns(|| {
        let mut watch = KernelDriftWatch {
            reach: reach(),
            port_vlans: vec![("pfm0".into(), Vec::new())],
            trunk_ports: Vec::new(),
            scope: DriftScope {
                scans_v6: true,
                ..DriftScope::default()
            },
            links: None,
        };
        let found = watch.uncovered(true).expect("scan");
        assert_eq!(
            found.lines,
            vec![
                "198.51.100.0/24 via pft0 (table 254)".to_string(),
                "192.0.2.128/26 via pft0 (table 100)".to_string(),
            ]
        );
        let V6Drift::Scanned(v6) = found.v6 else {
            panic!("the v6 half ran: {:?}", found.v6);
        };
        let lines: Vec<String> = v6.findings.iter().map(ToString::to_string).collect();
        assert!(
            lines.contains(&"2001:db8:1::/48 via pft0 (table 254)".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"2001:db8:2::/48 via pft0 (table 100)".to_string()),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("table 200")), "{lines:?}");
    });
}
