//! Feasibility probes for the completeness authority, grafted into
//! `packetframe feasibility` by the CLI (the `Module` trait has no
//! feasibility method; free functions are the established shape — see
//! `neigh-snoop`'s `probe_linux`).
//!
//! **Non-required**, like every other module probe: feasibility informs,
//! attach enforces. But the two conditions below are worth the
//! subprocess, because both produce the same symptom — a mirror that is
//! never attested, so a first steer defers forever — and neither is
//! visible in the config file. An operator reading `integrity-authority
//! frr upstream 192.0.2.1` cannot see that the address has a typo in it,
//! or that `vtysh` is not installed on this image.

use std::path::Path;

use packetframe_common::probe::Capability;

pub const CAP_VTYSH: &str = "fast-path.integrity-authority.vtysh";
pub const CAP_UPSTREAMS: &str = "fast-path.integrity-authority.upstreams";

/// Probe the FRR authority's two preconditions. `upstreams` is the
/// declared set; an empty slice skips the second probe.
pub fn run_frr_authority_probes(
    vtysh: Option<&Path>,
    upstreams: &[std::net::IpAddr],
) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        linux::run(vtysh, upstreams)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (vtysh, upstreams);
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Read as _;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    pub(super) fn run(vtysh: Option<&Path>, upstreams: &[IpAddr]) -> Vec<Capability> {
        let mut caps = Vec::new();
        // Same path rule as the runner: an explicit config path wins,
        // else `PACKETFRAME_VTYSH`, else the default. A probe that
        // resolved the path differently from the thing it is predicting
        // would be worse than no probe.
        let path: PathBuf = match vtysh {
            Some(p) => p.to_path_buf(),
            None => std::env::var_os(packetframe_common::frr::VTYSH_PATH_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(packetframe_common::frr::DEFAULT_VTYSH_PATH)),
        };

        let version = match vtysh_sync(&path, &["show version"]) {
            Ok(out) => {
                let first = out.lines().next().unwrap_or("").trim().to_string();
                caps.push(Capability::pass(
                    CAP_VTYSH,
                    format!("{} answers: {first}", path.display()),
                    false,
                ));
                true
            }
            Err(e) => {
                caps.push(Capability::fail(
                    CAP_VTYSH,
                    format!(
                        "{}: {e}. The FRR authority cannot run, nothing will attest the \
                         route mirror, and a first steer under `require-table-complete \
                         on` would defer forever",
                        path.display()
                    ),
                    false,
                ));
                false
            }
        };

        if !version || upstreams.is_empty() {
            return caps;
        }

        // A declared upstream FRR does not know about is the quiet
        // version of the same failure: every check reads it as "not
        // Established", the authority revokes on every tick, and
        // nothing ever steers. The config cannot be wrong on its own
        // terms — it is a valid IP — so this is the only place a typo
        // surfaces before a rollout window.
        let mut unknown = Vec::new();
        for peer in upstreams {
            match vtysh_sync(&path, &[&format!("show bgp neighbor {peer} json")]) {
                Ok(out) if out.contains(&peer.to_string()) => {}
                _ => unknown.push(peer.to_string()),
            }
        }
        caps.push(if unknown.is_empty() {
            Capability::pass(
                CAP_UPSTREAMS,
                format!("FRR knows all {} declared upstream(s)", upstreams.len()),
                false,
            )
        } else {
            Capability::fail(
                CAP_UPSTREAMS,
                format!(
                    "FRR has no neighbor {} — a declared upstream FRR does not know \
                     reads as \"not Established\" on every check, so the authority \
                     revokes eligibility forever and no steer is ever permitted. Check \
                     the address against `show bgp summary`",
                    unknown.join(", ")
                ),
                false,
            )
        });
        caps
    }

    /// Synchronous bounded `vtysh -c …`; feasibility is synchronous, so
    /// the async client cannot be reused here. Kills the child if it
    /// outlives the budget, and drains stdout on its own thread — a
    /// `show bgp neighbor` on a busy box fills the pipe, and a child
    /// blocked on write never exits for the `try_wait` loop.
    fn vtysh_sync(path: &Path, commands: &[&str]) -> Result<String, String> {
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
        let mut stdout = child.stdout.take().ok_or("no stdout pipe")?;
        let reader = std::thread::spawn(move || {
            let mut out = String::new();
            let _ = stdout.read_to_string(&mut out);
            out
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let out = reader.join().unwrap_or_default();
                    return if status.success() {
                        Ok(out)
                    } else {
                        Err(format!("exited {status}"))
                    };
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
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
}
