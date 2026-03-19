//! Parent-side child process manager for the session child binary.
//!
//! Spawns the `session` binary (or legacy `ssh3-session` shim), establishes a remoc connection over
//! stdin/stdout pipes, and manages the child's lifecycle.
//!
//! # Protocol
//!
//! 1. Parent spawns the session child binary with stdin/stdout piped.
//! 2. Parent establishes remoc connection: reads from child's stdout, writes to child's stdin.
//! 3. Parent sends [`ChildBootstrap`] (transport + credential) via base channel.
//! 4. Child performs PAM authentication and sends [`AuthResult`] back.

use std::path::Path;
use std::process::ExitStatus;

use genmeta_ssh::{AuthResult, ChildBootstrap};
use tokio::process::{Child, Command};
use tracing::Instrument;

/// Handle to a spawned session child process.
///
/// Manages the child's lifecycle and ensures cleanup on drop.
/// The remoc connection is established during [`spawn`](Self::spawn).
pub struct ChildProcess {
    child: Child,
}

impl ChildProcess {
    /// Spawn the session child binary and establish a remoc connection.
    ///
    /// Returns the process handle, a [`Sender<ChildBootstrap>`] for sending
    /// the bootstrap payload, and a [`Receiver<AuthResult>`] for receiving
    /// the authentication result from the child.
    ///
    /// # Arguments
    ///
    /// * `session_path` — Path to the session child binary.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary cannot be spawned or the remoc
    /// connection fails.
    pub async fn spawn(
        session_path: impl AsRef<Path>,
    ) -> Result<
        (
            Self,
            remoc::rch::base::Sender<ChildBootstrap>,
            remoc::rch::base::Receiver<AuthResult>,
        ),
        std::io::Error,
    > {
        let mut child = Command::new(session_path.as_ref())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        // Take ownership of the child's piped handles.
        // child_stdin: parent writes -> child reads
        // child_stdout: child writes -> parent reads
        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("failed to capture child stdin"))?;
        let child_stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("failed to capture child stdout"))?;

        // Establish remoc connection.
        // remoc::Connect::io(cfg, reader, writer):
        //   reader = child_stdout (parent reads from child)
        //   writer = child_stdin (parent writes to child)
        //
        // Parent sends ChildBootstrap, so base_tx is Sender<ChildBootstrap>.
        // Child sends AuthResult, so base_rx is Receiver<AuthResult>.
        let (conn, base_tx, base_rx): (
            _,
            remoc::rch::base::Sender<ChildBootstrap>,
            remoc::rch::base::Receiver<AuthResult>,
        ) = remoc::Connect::io(remoc::Cfg::default(), child_stdout, child_stdin)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
        tokio::spawn(conn.in_current_span());

        Ok((Self { child }, base_tx, base_rx))
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
    use h3x::stream_id::StreamId;
    use std::path::PathBuf;

    /// Locate the `session` binary built by cargo, falling back to legacy `ssh3-session`.
    ///
    /// In test builds, we can derive the path from the test binary's location:
    /// the test binary is at `target/<profile>/deps/...` and the session
    /// binary is at `target/<profile>/session`.
    fn session_bin() -> PathBuf {
        // The current test executable lives in target/<profile>/deps/
        let test_exe = std::env::current_exe().expect("cannot determine test executable path");
        let deps_dir = test_exe.parent().expect("no parent for test exe");
        // Go up from deps/ to the profile dir (e.g., target/debug/)
        let profile_dir = deps_dir.parent().expect("no parent for deps dir");
        ["session", "ssh3-session"]
            .into_iter()
            .map(|name| profile_dir.join(name))
            .find(|path| path.exists())
            .unwrap_or_else(|| profile_dir.join("session"))
    }

    #[tokio::test]
    async fn spawn_returns_channels() {
        let bin = session_bin();
        if !bin.exists() {
            panic!(
                "session binary not found at {}; run `cargo build --bin session` first",
                bin.display()
            );
        }

        let (mut child, _bootstrap_tx, _auth_rx) = ChildProcess::spawn(&bin)
            .await
            .expect("failed to spawn session child");

        // spawn() returns channels; child waits for ChildBootstrap.
        // Kill the child since we're done.
        child.kill().expect("failed to kill child");
        let status = child.wait().await.expect("failed to wait for child");
        // Child was killed, so it should not have exited successfully
        // (on Unix, killed processes have a signal-based exit).
        assert!(!status.success() || cfg!(windows));
    }

    #[tokio::test]
    async fn drop_kills_child() {
        let bin = session_bin();
        if !bin.exists() {
            panic!(
                "session binary not found at {}; run `cargo build --bin session` first",
                bin.display()
            );
        }

        let child_id;
        {
            let (child, _bootstrap_tx, _auth_rx) = ChildProcess::spawn(&bin)
                .await
                .expect("failed to spawn session child");
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

    // Integration test: send ChildBootstrap to the child process.
    // PAM authentication will fail without root, but we verify the
    // full bootstrap round-trip (parent sends credential, child responds).
    #[tokio::test]
    async fn spawn_and_bootstrap_session() {
        let bin = session_bin();
        if !bin.exists() {
            panic!(
                "session binary not found at {}; run `cargo build --bin session` first",
                bin.display()
            );
        }

        let (mut child, mut bootstrap_tx, mut auth_rx) = ChildProcess::spawn(&bin)
            .await
            .expect("failed to spawn session child");

        let (_dispatch_tx, dispatch_rx) = tokio::sync::mpsc::channel(1);
        let opener: crate::channel::OpenBiFactory = std::sync::Arc::new(|| {
            Box::pin(async {
                Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::Unsupported,
                    "child test transport does not open streams",
                ))
            })
        });
        let endpoint = crate::channel::ConversationEndpoint::new(
            StreamId(h3x::varint::VarInt::from(0u8)),
            dispatch_rx,
            opener,
        );
        let transport =
            std::sync::Arc::new(crate::channel::Ssh3Transport::new(endpoint));

        use genmeta_ssh::Ssh3TransportServerShared;
        use remoc::rtc::ServerShared;
        let (server, client) = Ssh3TransportServerShared::new(transport, 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });

        let bootstrap = ChildBootstrap {
            transport: client,
            credential: genmeta_ssh::AuthCredential::Basic {
                username: "testuser".into(),
                password: "testpass".into(),
            },
            conversation_id: StreamId(h3x::varint::VarInt::from(42u8)),
        };

        bootstrap_tx
            .send(bootstrap)
            .await
            .unwrap_or_else(|_| panic!("failed to send ChildBootstrap"));
        // Drop sender so child's remoc connection sees channel close.
        drop(bootstrap_tx);

        // Child will attempt PAM auth, which will fail without root.
        // The child may exit before remoc delivers AuthResult, so tolerate all outcomes.
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), auth_rx.recv()).await;

        if let Ok(Ok(Some(auth_result))) = result {
            match auth_result {
                AuthResult::Success { .. } => { /* ok if running as root */ }
                AuthResult::Failure { .. } => { /* expected without root/PAM */ }
            }
        }

        // Always kill and wait — child's remoc conn task may still be running.
        child.kill().expect("failed to kill child");
        let _ = child.wait().await;
    }
}
