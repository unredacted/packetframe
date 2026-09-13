//! neigh-snoop feasibility probes, grafted into `packetframe
//! feasibility` by the CLI (the `Module` trait has no feasibility
//! method; free functions are the established shape).
//!
//! All probes are **non-required**: feasibility informs, attach
//! enforces. An absent bridge is a *warning*, not a failure: the module
//! tracks bridges by name and waits for them.

use std::path::Path;

use packetframe_common::probe::Capability;

/// Run the probes for the configured bridges and persist directory;
/// `gate_lists` is the `frr-gate` `(v4, v6)` list pair when configured.
pub fn run_feasibility_probes(
    bridges: &[String],
    persist_dir: &Path,
    gate_lists: Option<(&str, &str)>,
) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        run(bridges, persist_dir, gate_lists)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bridges, persist_dir, gate_lists);
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn run(
    bridges: &[String],
    persist_dir: &Path,
    gate_lists: Option<(&str, &str)>,
) -> Vec<Capability> {
    let mut caps = Vec::new();

    // AF_PACKET needs CAP_NET_RAW; opening and closing one socket is
    // the whole test.
    caps.push({
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            Capability::pass(
                "neigh-snoop.socket.af_packet",
                "AF_PACKET socket creatable (CAP_NET_RAW)",
                false,
            )
        } else {
            let e = std::io::Error::last_os_error();
            Capability::fail(
                "neigh-snoop.socket.af_packet",
                format!("socket(AF_PACKET) failed: {e}; the capture needs CAP_NET_RAW"),
                false,
            )
        }
    });

    // CAP_NET_ADMIN (bit 12) for RTM_NEWNEIGH, CAP_NET_RAW (bit 13)
    // for the capture, from /proc/self/status CapEff. No trial
    // neighbour write here: feasibility must have no side effects.
    caps.push(match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => match s
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        {
            Some(eff) => {
                let missing: Vec<&str> = [(12, "CAP_NET_ADMIN"), (13, "CAP_NET_RAW")]
                    .into_iter()
                    .filter(|(bit, _)| eff & (1u64 << bit) == 0)
                    .map(|(_, n)| n)
                    .collect();
                if missing.is_empty() {
                    Capability::pass(
                        "neigh-snoop.caps.net_admin",
                        "CAP_NET_ADMIN and CAP_NET_RAW effective",
                        false,
                    )
                } else {
                    Capability::fail(
                        "neigh-snoop.caps.net_admin",
                        format!("missing: {}", missing.join(", ")),
                        false,
                    )
                }
            }
            None => Capability::unknown(
                "neigh-snoop.caps.net_admin",
                "CapEff not found in /proc/self/status",
                false,
            ),
        },
        Err(e) => Capability::unknown(
            "neigh-snoop.caps.net_admin",
            format!("could not read /proc/self/status ({e})"),
            false,
        ),
    });

    for iface in bridges {
        let sys = Path::new("/sys/class/net").join(iface);
        let name = format!("neigh-snoop.iface.{iface}");
        if !sys.exists() {
            caps.push(Capability::warn(
                name,
                format!("{iface} is absent now; the module waits for RTM_NEWLINK by name"),
                false,
            ));
            continue;
        }
        let ifindex = std::fs::read_to_string(sys.join("ifindex"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "?".into());
        if sys.join("bridge").is_dir() {
            caps.push(Capability::pass(
                name,
                format!("bridge, ifindex {ifindex}"),
                false,
            ));
        } else {
            caps.push(Capability::warn(
                name,
                format!(
                    "exists (ifindex {ifindex}) but is not a bridge; ARP/ND is still visible \
                     on any L2 device"
                ),
                false,
            ));
        }
    }

    caps.push(match persist_dir_state(persist_dir) {
        Ok(msg) => Capability::pass("neigh-snoop.persist-dir", msg, false),
        Err(msg) => Capability::fail("neigh-snoop.persist-dir", msg, false),
    });

    if let Some((v4, v6)) = gate_lists {
        // vtysh present and answering. Same path rule as the runner.
        let vtysh = crate::frr_gate::RealVtysh::from_env(std::time::Duration::from_secs(5));
        let path = vtysh.path().to_path_buf();
        match vtysh_sync(&path, &["show version"]) {
            Ok(out) => {
                let first = out.lines().next().unwrap_or("").trim().to_string();
                caps.push(Capability::pass(
                    "neigh-snoop.frr.vtysh",
                    format!("{} answers: {first}", path.display()),
                    false,
                ));
                // The two gate lists must exist (the static FRR half);
                // absent means the gate idles until it is uploaded.
                let mut missing = Vec::new();
                for (fam, name) in [("ip", v4), ("ipv6", v6)] {
                    match vtysh_sync(&path, &[&format!("show {fam} prefix-list {name}")]) {
                        Ok(text) if crate::frr_gate::parse_prefix_list(&text).present => {}
                        _ => missing.push(name.to_string()),
                    }
                }
                caps.push(if missing.is_empty() {
                    Capability::pass(
                        "neigh-snoop.frr.gate-lists",
                        format!("prefix-lists {v4} and {v6} exist"),
                        false,
                    )
                } else {
                    Capability::warn(
                        "neigh-snoop.frr.gate-lists",
                        format!(
                            "prefix-list(s) {} absent; the gate idles until the static FRR \
                             configuration is uploaded",
                            missing.join(", ")
                        ),
                        false,
                    )
                });
            }
            Err(e) => caps.push(Capability::fail(
                "neigh-snoop.frr.vtysh",
                format!("{}: {e}; frr-gate cannot reconcile", path.display()),
                false,
            )),
        }
    }

    caps
}

/// Synchronous bounded `vtysh -c …` for the probe (feasibility is
/// synchronous). Kills the child if it outlives the budget.
#[cfg(target_os = "linux")]
fn vtysh_sync(path: &Path, commands: &[&str]) -> Result<String, String> {
    use std::io::Read as _;
    let mut cmd = std::process::Command::new(path);
    for c in commands {
        cmd.arg("-c").arg(c);
    }
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    // Drain stdout on its own thread: a prefix-list with thousands of
    // runtime entries fills the pipe, and a child blocked on write never
    // exits for the try_wait loop below.
    let mut stdout = child.stdout.take().ok_or("no stdout pipe")?;
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        let _ = stdout.read_to_string(&mut out);
        out
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().unwrap_or_default();
                if !status.success() {
                    return Err(format!("exited {status}"));
                }
                return Ok(out);
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timed out after 5s".into());
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    }
}

/// Writable now, creatable at load, or neither. An existing
/// non-directory is "neither": `create_dir_all` at load cannot replace
/// it, so feasibility must not promise it will.
#[cfg(target_os = "linux")]
fn persist_dir_state(dir: &Path) -> Result<String, String> {
    if dir.exists() && !dir.is_dir() {
        return Err(format!("{} exists but is not a directory", dir.display()));
    }
    if dir.is_dir() {
        let probe = dir.join(format!(".feasibility-{}", std::process::id()));
        return match std::fs::write(&probe, b"") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
                Ok(format!("{} exists and is writable", dir.display()))
            }
            Err(e) => Err(format!("{} exists but is not writable: {e}", dir.display())),
        };
    }
    match dir.parent() {
        Some(p) if p.is_dir() => Ok(format!(
            "{} will be created at load (parent exists)",
            dir.display()
        )),
        Some(p) => Err(format!(
            "{} and its parent {} do not exist",
            dir.display(),
            p.display()
        )),
        None => Err(format!("{} has no parent", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_returns_nothing() {
        let caps = super::run_feasibility_probes(
            &["br0".to_string()],
            std::path::Path::new("/var/lib/packetframe/state/neigh-cache"),
            Some(("A", "B")),
        );
        assert!(caps.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_each_probe_family() {
        let dir = std::env::temp_dir().join(format!("pf-snoop-probe-{}", std::process::id()));
        let caps = super::run_feasibility_probes(&["definitely-absent0".to_string()], &dir, None);
        let names: Vec<&str> = caps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"neigh-snoop.socket.af_packet"));
        assert!(names.contains(&"neigh-snoop.caps.net_admin"));
        assert!(names.contains(&"neigh-snoop.iface.definitely-absent0"));
        assert!(names.contains(&"neigh-snoop.persist-dir"));
        assert!(caps.iter().all(|c| !c.required));
    }
}
