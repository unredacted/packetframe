//! neigh-snoop feasibility probes, grafted into `packetframe
//! feasibility` by the CLI (the `Module` trait has no feasibility
//! method; free functions are the established shape).
//!
//! All probes are **non-required**: feasibility informs, attach
//! enforces. An absent bridge is a *warning*, not a failure: the module
//! tracks bridges by name and waits for them.

use std::path::Path;

use packetframe_common::probe::Capability;

/// Run the probes for the configured bridges and persist directory.
pub fn run_feasibility_probes(bridges: &[String], persist_dir: &Path) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        run(bridges, persist_dir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (bridges, persist_dir);
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn run(bridges: &[String], persist_dir: &Path) -> Vec<Capability> {
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

    caps
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
        );
        assert!(caps.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_each_probe_family() {
        let dir = std::env::temp_dir().join(format!("pf-snoop-probe-{}", std::process::id()));
        let caps = super::run_feasibility_probes(&["definitely-absent0".to_string()], &dir);
        let names: Vec<&str> = caps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"neigh-snoop.socket.af_packet"));
        assert!(names.contains(&"neigh-snoop.caps.net_admin"));
        assert!(names.contains(&"neigh-snoop.iface.definitely-absent0"));
        assert!(names.contains(&"neigh-snoop.persist-dir"));
        assert!(caps.iter().all(|c| !c.required));
    }
}
