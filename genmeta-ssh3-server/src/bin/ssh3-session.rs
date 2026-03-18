//! SSH3 session child process binary.
//!
//! Spawned by the main server process to handle a single SSH3 conversation.
//! Communicates with the parent via remoc over stdin/stdout.
//!
//! # Protocol
//!
//! 1. Parent spawns this binary with stdin/stdout piped.
//! 2. Child establishes a remoc connection over stdin (read) / stdout (write).
//! 3. Child receives [`ChildBootstrap`] from parent (transport client + credential).
//! 4. Child performs PAM authentication using the credential.
//! 5. Child sends [`AuthResult`] back to parent.
//! 6. On success: constructs [`SessionInit`], calls `session.run(transport, init)`.
//! 7. On failure: exits after sending `AuthResult::Failure`.

use genmeta_ssh3_proto::auth::AuthCredential;
use genmeta_ssh3_proto::session::{AuthResult, ChildBootstrap};
#[cfg(feature = "pam")]
use genmeta_ssh3_server::auth::pam::{pam_authenticate, SystemPam};
use genmeta_ssh3_server::session_driver::Ssh3Session;
use tracing::Instrument;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing to stderr (stdout is used for remoc transport).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("ssh3-session child process starting");

    // Establish remoc connection over stdin (read) / stdout (write).
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (conn, mut base_tx, mut base_rx): (
        _,
        remoc::rch::base::Sender<AuthResult>,
        remoc::rch::base::Receiver<ChildBootstrap>,
    ) = remoc::Connect::io(remoc::Cfg::default(), stdin, stdout).await?;
    tokio::spawn(conn.in_current_span());

    tracing::debug!("remoc connection established");

    // Receive bootstrap payload from parent (transport client + credential).
    let bootstrap = base_rx
        .recv()
        .await
        .map_err(std::io::Error::other)?
        .ok_or("parent closed base channel without sending ChildBootstrap")?;

    tracing::debug!("received ChildBootstrap from parent");

    // Extract username and password from credential.
    let AuthCredential::Basic { username, password } = bootstrap.credential;
    let conversation_id = bootstrap.conversation_id;

    // Perform PAM authentication BEFORE session.run() (must run as root).
    let auth_result = run_pam_auth(&username, &password).await;

    match &auth_result {
        AuthResult::Failure { reason } => {
            tracing::warn!(reason, "PAM authentication failed");
            let _ = base_tx.send(auth_result).await;
            return Ok(());
        }
        AuthResult::Success { .. } => {
            base_tx.send(auth_result.clone()).await?;
            tracing::debug!("sent AuthResult::Success to parent");
        }
    }

    // On success, construct SessionInit and run the session.
    if let AuthResult::Success {
        uid,
        gid,
        home,
        shell,
    } = auth_result
    {
        let init = genmeta_ssh3_proto::session::SessionInit {
            conversation_id,
            username,
            uid,
            gid,
            home,
            shell,
        };

        let session = Ssh3Session::new(bootstrap.transport, init);
        session.run().await?;
    }

    tracing::info!("ssh3-session child process exiting");
    Ok(())
}

/// Perform PAM authentication and convert the result to proto's [`AuthResult`].
#[cfg(feature = "pam")]
async fn run_pam_auth(username: &str, password: &str) -> AuthResult {
    let pam_backend = SystemPam;
    match pam_authenticate(&pam_backend, username, password).await {
        Ok(genmeta_ssh3_server::auth::pam::AuthResult::Success {
            uid,
            gid,
            home,
            shell,
        }) => AuthResult::Success {
            uid,
            gid,
            home,
            shell,
        },
        Ok(genmeta_ssh3_server::auth::pam::AuthResult::Failure { reason }) => {
            AuthResult::Failure { reason }
        }
        Err(pam_err) => AuthResult::Failure {
            reason: pam_err.to_string(),
        },
    }
}

/// Stub for builds without the `pam` feature — always fails.
#[cfg(not(feature = "pam"))]
async fn run_pam_auth(_username: &str, _password: &str) -> AuthResult {
    AuthResult::Failure {
        reason: "PAM support not compiled (missing `pam` feature)".into(),
    }
}
