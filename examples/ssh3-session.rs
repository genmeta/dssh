//! SSH3 session child process.
//!
//! Launched by the gateway (ssh3-server) as a privilege-separated subprocess.
//! Communicates with the parent via a remoc channel over stdin/stdout using
//! nested [`RFnOnce`](remoc::rfn::RFnOnce) remote functions.
//!
//! Flow:
//! 1. Create a nested `AuthenticateFn` closure and send it to the parent
//! 2. Parent calls the outer fn with [`AuthRequest`] → child runs PAM
//! 3. On success, return inner `StartSessionFn` to parent
//! 4. Parent calls inner fn with [`SessionBootstrap`] → child drops
//!    privileges and runs the session dispatcher

use std::sync::Arc;

use genmeta_ssh::{
    auth::AuthCredential,
    conversation::Conversation,
    session::{
        AuthError, AuthRequest, SessionBootstrap, SessionRunError, StartSessionFn,
        dispatcher::{SessionConfig, run_session},
        privilege::drop_privileges,
    },
};
use snafu::Report;
use tracing::Instrument;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Establish remoc channel over stdin/stdout.
    // Parent receives AuthenticateFn; child sends it.
    let (conn, mut tx, _rx) = remoc::Connect::io::<
        _,
        _,
        genmeta_ssh::session::AuthenticateFn,
        (),
        remoc::codec::Default,
    >(remoc::Cfg::default(), stdin, stdout)
    .await
    .expect("failed to establish remoc channel");
    let conn_handle = tokio::spawn(conn.instrument(tracing::info_span!("remoc_conn")));

    // Create the outer RFnOnce: authentication.
    let auth_fn = remoc::rfn::RFnOnce::new_1(|auth_request: AuthRequest| async move {
        tracing::info!(username = %auth_request.username, credential = %auth_request.credential, "authentication starting");

        let (uid, gid, shell) = match &auth_request.credential {
            AuthCredential::Basic { password, .. } => {
                let user_info = genmeta_ssh::session::pam::authenticate(
                    "sshd",
                    &auth_request.username,
                    password,
                )
                .await
                .map_err(|e| AuthError::PamFailed {
                    reason: Report::from_error(e).to_string(),
                })?;
                (user_info.uid, user_info.gid, user_info.shell)
            }
            AuthCredential::Certificate => {
                let user_info =
                    genmeta_ssh::session::pam::open_session("sshd", &auth_request.username)
                        .await
                        .map_err(|e| AuthError::PamFailed {
                            reason: Report::from_error(e).to_string(),
                        })?;
                (user_info.uid, user_info.gid, user_info.shell)
            }
        };

        tracing::info!(uid, gid, "authentication succeeded");

        // Capture user info into the inner closure.
        let username = auth_request.username;

        // Create the inner RFnOnce: drop privileges + run session.
        let start_session_fn: StartSessionFn =
            remoc::rfn::RFnOnce::new_1(move |bootstrap: SessionBootstrap| async move {
                tracing::info!(%username, "starting session");

                // PAM open_session (leak — close_session requires root).
                // TODO: open_session before drop_privileges

                // Drop privileges from root to target user.
                if nix::unistd::getuid().is_root() {
                    drop_privileges(uid, gid, &username).map_err(|e| {
                        SessionRunError::DropPrivileges {
                            reason: Report::from_error(e).to_string(),
                        }
                    })?;
                    tracing::info!(uid, gid, "privileges dropped");
                }

                // Build Conversation from remoc-proxied streams.
                let control_reader = bootstrap.control_reader.into_box_reader();
                let control_writer = bootstrap.control_writer.into_box_writer();

                let conversation = Arc::new(Conversation::new(
                    bootstrap.conversation_id,
                    bootstrap.peer_version,
                    control_reader,
                    control_writer,
                    bootstrap.manage_stream,
                ));

                let config = SessionConfig {
                    shell,
                    ..Default::default()
                };

                tracing::info!("session dispatcher starting");
                run_session(conversation, config).await;
                tracing::info!("session ended");
                Ok(())
            });

        Ok(start_session_fn)
    });

    tx.send(auth_fn)
        .await
        .expect("failed to send AuthenticateFn to parent");

    // Wait for remoc connection to close (rfn tasks run in background).
    let _ = conn_handle.await;
    tracing::info!("child process exiting");
}
