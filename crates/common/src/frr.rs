//! One `vtysh` invoker, for every module that asks FRR a question.
//!
//! Two do: neigh-snoop's next-hop gate writes prefix lists, and the
//! custom-FIB's FRR completeness authority reads counts, session state
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
}

impl RealVtysh {
    /// Path from [`VTYSH_PATH_ENV`] if set, else [`DEFAULT_VTYSH_PATH`].
    pub fn from_env(timeout: Duration) -> Self {
        let path = std::env::var_os(VTYSH_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_VTYSH_PATH));
        Self { path, timeout }
    }

    /// An explicit path — for a caller whose config names one.
    pub fn at(path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            path: path.into(),
            timeout,
        }
    }

    pub fn path(&self) -> &Path {
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
                    String::from_utf8_lossy(&out.stderr).trim()
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
}
