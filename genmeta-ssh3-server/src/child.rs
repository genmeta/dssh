//! Parent-side child process manager for ssh3-session.
//!
//! Spawns the `ssh3-session` binary, establishes a remoc RTC connection over
//! stdin/stdout pipes, and manages the child's lifecycle.
//!
//! # Protocol
//!
//! 1. Parent spawns `ssh3-session` with stdin/stdout piped.
//! 2. Parent establishes remoc connection: reads from child's stdout, writes to child's stdin.
//! 3. Child creates [`SshSessionServerShared`] and sends [`SshSessionClient`] via base channel.
//! 4. Parent receives the client proxy and uses it for RTC calls.

use std::path::Path;
use std::process::ExitStatus;

use genmeta_ssh3_proto::session::SshSessionClient;
use tokio::process::{Child, Command};

/// Handle to a spawned `ssh3-session` child process.
///
/// Manages the child's lifecycle and ensures cleanup on drop.
/// The remoc connection and RTC client are established during [`spawn`](Self::spawn).
pub struct ChildProcess {
    child: Child,
}

impl ChildProcess {
    /// Spawn the `ssh3-session` binary and establish a remoc RTC connection.
    ///
    /// Returns the process handle and an [`SshSessionClient`] proxy for
    /// making remote calls to the child.
    ///
    /// # Arguments
    ///
    /// * `ssh3_session_path` — Path to the `ssh3-session` binary.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary cannot be spawned, the remoc connection
    /// fails, or the child does not send the client proxy.
    pub async fn spawn(
        ssh3_session_path: impl AsRef<Path>,
    ) -> Result<(Self, SshSessionClient), std::io::Error> {
        let mut child = Command::new(ssh3_session_path.as_ref())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        // Take ownership of the child's piped handles.
        // child_stdin: parent writes -> child reads
        // child_stdout: child writes -> parent reads
        let child_stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::other("failed to capture child stdin")
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::other("failed to capture child stdout")
        })?;

        // Establish remoc connection.
        // remoc::Connect::io(cfg, reader, writer):
        //   reader = child_stdout (parent reads from child)
        //   writer = child_stdin (parent writes to child)
        //
        // The child sends SshSessionClient, so our base_rx is Receiver<SshSessionClient>.
        // The child expects Receiver<()>, so our base_tx is Sender<()>.
        let (conn, _base_tx, mut base_rx): (
            _,
            remoc::rch::base::Sender<()>,
            remoc::rch::base::Receiver<SshSessionClient>,
        ) = remoc::Connect::io(remoc::Cfg::default(), child_stdout, child_stdin)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
        tokio::spawn(conn);

        // Receive the SshSessionClient from the child.
        let client = base_rx
            .recv()
            .await
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, e.to_string())
            })?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "child closed base channel without sending client",
                )
            })?;

        tracing::debug!("received SshSessionClient from child");

        Ok((Self { child }, client))
    }

    /// Wait for the child process to exit and return its status.
    pub async fn wait(&mut self) -> Result<ExitStatus, std::io::Error> {
        self.child.wait().await
    }

    /// Force-terminate the child process.
    pub fn kill(&mut self) -> Result<(), std::io::Error> {
        self.child.start_kill()
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // Best-effort kill — ignore errors (child may have already exited).
        let _ = self.child.start_kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::session::{SessionInit, SshSession};
    use std::path::PathBuf;

    /// Locate the `ssh3-session` binary built by cargo.
    ///
    /// In test builds, we can derive the path from the test binary's location:
    /// the test binary is at `target/<profile>/deps/...` and the ssh3-session
    /// binary is at `target/<profile>/ssh3-session`.
    fn ssh3_session_bin() -> PathBuf {
        // The current test executable lives in target/<profile>/deps/
        let test_exe = std::env::current_exe().expect("cannot determine test executable path");
        let deps_dir = test_exe.parent().expect("no parent for test exe");
        // Go up from deps/ to the profile dir (e.g., target/debug/)
        let profile_dir = deps_dir.parent().expect("no parent for deps dir");
        profile_dir.join("ssh3-session")
    }

    #[tokio::test]
    async fn spawn_returns_client() {
        let bin = ssh3_session_bin();
        if !bin.exists() {
            panic!(
                "ssh3-session binary not found at {}; run `cargo build --bin ssh3-session` first",
                bin.display()
            );
        }

        let (mut child, _client) = ChildProcess::spawn(&bin)
            .await
            .expect("failed to spawn ssh3-session");

        // The client is a valid SshSessionClient proxy.
        // Kill the child since we're done.
        child.kill().expect("failed to kill child");
        let status = child.wait().await.expect("failed to wait for child");
        // Child was killed, so it should not have exited successfully
        // (on Unix, killed processes have a signal-based exit).
        assert!(!status.success() || cfg!(windows));
    }

    #[tokio::test]
    async fn drop_kills_child() {
        let bin = ssh3_session_bin();
        if !bin.exists() {
            panic!(
                "ssh3-session binary not found at {}; run `cargo build --bin ssh3-session` first",
                bin.display()
            );
        }

        let child_id;
        {
            let (child, _client) = ChildProcess::spawn(&bin)
                .await
                .expect("failed to spawn ssh3-session");
            child_id = child.child.id();
            // Drop child here — should kill the process.
        }

        // Give the OS a moment to clean up.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify the child process is no longer running.
        if let Some(pid) = child_id {
            // On Unix, kill(pid, 0) returns error if process doesn't exist.
            let result = unsafe { libc::kill(pid as i32, 0) };
            assert_ne!(
                result, 0,
                "child process {pid} should have been killed on drop"
            );
        }
    }

    #[tokio::test]
    async fn spawn_and_call_run_session() {
        let bin = ssh3_session_bin();
        if !bin.exists() {
            panic!(
                "ssh3-session binary not found at {}; run `cargo build --bin ssh3-session` first",
                bin.display()
            );
        }

        let (mut child, client) = ChildProcess::spawn(&bin)
            .await
            .expect("failed to spawn ssh3-session");

        // Call run_session on the child via RTC.
        let init = SessionInit {
            conversation_id: 42,
            username: "testuser".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/tmp"),
            shell: PathBuf::from("/bin/sh"),
        };

        // The child runs with cfg(test) drop_privileges (no-op), so this
        // should succeed. However the child binary is NOT compiled with
        // cfg(test), so setuid/setgid will be attempted and may fail if
        // we're not root. We tolerate the error here — the important thing
        // is that the RTC call completes (doesn't hang or panic).
        // Two separate channel pairs to avoid loopback (writing to to_client
        // would feed back into from_client if using the same pair).
        let (_from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(_from_tx);
        let (oc_tx, _oc_rx) = remoc::rch::mpsc::channel(16);
        let result = client.run_session(init, from_rx, to_tx, oc_tx).await;
        tracing::info!(?result, "run_session result");

        // Clean up.
        child.kill().expect("failed to kill child");
        let _ = child.wait().await;
    }
}
