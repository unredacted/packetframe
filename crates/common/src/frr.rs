//! One `vtysh` invoker, for every module that asks FRR a question.
//!
//! Two do: neigh-snoop's next-hop gate writes prefix lists, and the
//! PacketFrame FIB's FRR completeness authority reads counts, session state
//! and the running config. They had the same 50 lines of subprocess
//! handling, and the parts that matter are exactly the parts a second
//! copy gets wrong — `kill_on_drop`, so a timeout kills a wedged vtysh
//! instead of orphaning it, and `PACKETFRAME_VTYSH`, which is how the
//! netns tests point both of them at a fake.
//!
//! Deliberately NOT a parser. Each caller knows what it asked for and
//! what shape the answer takes; this owns the invocation and nothing
//! else.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

/// The default `vtysh` location on the reference fleet.
pub const DEFAULT_VTYSH_PATH: &str = "/usr/bin/vtysh";

/// The environment override the test doubles use.
pub const VTYSH_PATH_ENV: &str = "PACKETFRAME_VTYSH";

/// `vtysh -c <cmd> [-c <cmd> …]`, as one call.
///
/// One method, so a fake is one method. Commands are batched into a
/// single invocation because that is how `vtysh` is cheapest and,
/// more importantly, because two commands in one process see one
/// consistent view of FRR — which is what lets a caller sample a count
/// and the session state it qualifies without a second round trip
/// opening a gap between them.
pub trait Vtysh: Send + Sync {
    fn run<'a>(
        &'a self,
        commands: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}

/// The real `vtysh`: a bounded child process.
pub struct RealVtysh {
    path: PathBuf,
    timeout: Duration,
    daemon: Option<&'static str>,
}

impl RealVtysh {
    /// Path from [`VTYSH_PATH_ENV`] if set, else [`DEFAULT_VTYSH_PATH`].
    pub fn from_env(timeout: Duration) -> Self {
        let path = std::env::var_os(VTYSH_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_VTYSH_PATH));
        Self {
            path,
            timeout,
            daemon: None,
        }
    }

    /// An explicit path — for a caller whose config names one.
    pub fn at(path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            path: path.into(),
            timeout,
            daemon: None,
        }
    }

    /// Talk to one daemon only: `vtysh -d <daemon> -c …`.
    ///
    /// Without it, vtysh fans every command out to each daemon that
    /// implements it. On FRR 10 with mgmtd running, the copy of a
    /// prefix-list or route-map command meant for zebra goes through
    /// mgmtd, which takes the candidate and running datastore locks for
    /// an implicit commit and waits for zebra to apply it. When another
    /// session holds those locks, or a commit is stuck waiting on its
    /// backend (up to mgmtd's 600 s backend timeout), the command fails
    /// with `% command failed, could not lock candidate DS`. vtysh tries
    /// mgmtd first and stops there, so bgpd never sees the command
    /// either. A caller whose commands only matter to one daemon names
    /// it here, and mgmtd is never involved.
    pub fn only(mut self, daemon: &'static str) -> Self {
        self.daemon = Some(daemon);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The argument vector for one call: `[-d <daemon>] -c <cmd> …`.
    pub fn args(&self, commands: &[String]) -> Vec<String> {
        let mut args = Vec::with_capacity(commands.len() * 2 + 2);
        if let Some(d) = self.daemon {
            args.push("-d".to_string());
            args.push(d.to_string());
        }
        for c in commands {
            args.push("-c".to_string());
            args.push(c.clone());
        }
        args
    }
}

/// How many trailing output lines a failure keeps.
const FAILURE_TAIL_LINES: usize = 6;

/// What a failed `vtysh` said, for the error string.
///
/// vtysh prints a command's own error (`% Unknown command`, `% command
/// failed, could not lock candidate DS`, …) on its **stdout**, the same
/// stream as a command's output, and exits non-zero. stderr carries only
/// vtysh's own complaints (cannot connect, no such daemon). So both
/// streams count: stderr first, then the tail of stdout, where the
/// error that stopped vtysh is, since it exits at the first command
/// that fails. Bounded, because a failing batch can follow a long show
/// output.
pub fn failure_detail(stdout: &str, stderr: &str) -> String {
    let tail = |s: &str| -> Vec<String> {
        let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        let skip = lines.len().saturating_sub(FAILURE_TAIL_LINES);
        lines[skip..].iter().map(|l| l.to_string()).collect()
    };
    let mut parts = tail(stderr);
    parts.extend(tail(stdout));
    if parts.is_empty() {
        "no output".to_string()
    } else {
        parts.join(" | ")
    }
}

impl Vtysh for RealVtysh {
    fn run<'a>(
        &'a self,
        commands: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut cmd = tokio::process::Command::new(&self.path);
            cmd.args(self.args(commands));
            cmd.stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                // Without this the timeout below is a lie: the future
                // is dropped and the wedged vtysh keeps running,
                // holding whatever it holds, and the next tick starts
                // another one.
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
                    failure_detail(
                        &String::from_utf8_lossy(&out.stdout),
                        &String::from_utf8_lossy(&out.stderr)
                    )
                ));
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A call that outlives its budget is an `Err`, not a hang and not a
    /// partial `Ok` — which is what lets the callers classify it as an
    /// observation failure. `/bin/sh` stands in for `vtysh` because the
    /// invocation is `<path> -c <cmd>`, which `sh` runs.
    #[tokio::test]
    async fn a_call_past_its_budget_is_an_error() {
        let slow = RealVtysh::at("/bin/sh", Duration::from_millis(100));
        let err = slow
            .run(&["sleep 5".to_string()])
            .await
            .expect_err("a call past its budget must fail");
        assert!(err.starts_with("vtysh timed out after"), "{err}");
    }

    /// A stand-in that echoes its argv and then fails the way FRR 10's
    /// vtysh does when mgmtd cannot lock the candidate datastore: the
    /// error on stdout, nothing on stderr, exit 1.
    fn locked_vtysh(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("vtysh");
        std::fs::write(
            &path,
            "#!/bin/sh\necho \"args: $*\"\necho '% command failed, could not lock candidate DS'\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pf-frr-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The error that stopped vtysh reaches the caller even though vtysh
    /// put it on stdout. The first version reported stderr only, and a
    /// gate that failed for nine days said `vtysh exited exit status: 1:`
    /// and nothing else.
    #[tokio::test]
    async fn a_failure_carries_what_vtysh_printed_on_stdout() {
        let dir = scratch("stdout");
        let v = RealVtysh::at(locked_vtysh(&dir), Duration::from_secs(5));
        let err = v
            .run(&["configure terminal".to_string()])
            .await
            .expect_err("exit 1 is an error");
        assert!(err.starts_with("vtysh exited"), "{err}");
        assert!(err.contains("could not lock candidate DS"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// `only` puts `-d <daemon>` ahead of the commands, so vtysh connects
    /// to that daemon alone.
    #[tokio::test]
    async fn only_targets_one_daemon() {
        let dir = scratch("only");
        let v = RealVtysh::at(locked_vtysh(&dir), Duration::from_secs(5)).only("bgpd");
        let err = v
            .run(&["configure terminal".to_string(), "end".to_string()])
            .await
            .unwrap_err();
        assert!(
            err.contains("args: -d bgpd -c configure terminal -c end"),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn args_without_a_daemon_are_the_commands_alone() {
        let v = RealVtysh::at("/usr/bin/vtysh", Duration::from_secs(1));
        assert_eq!(
            v.args(&["show version".to_string()]),
            ["-c", "show version"]
        );
    }

    #[test]
    fn failure_detail_keeps_both_streams_and_bounds_stdout() {
        assert_eq!(failure_detail("", ""), "no output");
        assert_eq!(
            failure_detail("", "Exiting: failed to connect to any daemons.\n"),
            "Exiting: failed to connect to any daemons."
        );
        let mut long = String::new();
        for i in 0..100 {
            long.push_str(&format!("   seq {i} permit 192.0.2.{i}/32\n"));
        }
        long.push_str("% command failed, could not lock candidate DS\n");
        let d = failure_detail(&long, "warning\n");
        assert!(d.starts_with("warning | "), "{d}");
        assert!(d.ends_with("could not lock candidate DS"), "{d}");
        assert_eq!(d.split(" | ").count(), 1 + FAILURE_TAIL_LINES, "{d}");
    }
}
