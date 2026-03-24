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
    tracing_subscriber::fmt::init();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Establish remoc channel over stdin/stdout.
    // Parent receives AuthenticateFn; child sends it.
    let (conn, mut tx, _rx) =
        remoc::Connect::io::<_, _, genmeta_ssh::session::AuthenticateFn, (), remoc::codec::Default>(
            remoc::Cfg::default(),
            stdin,
            stdout,
        )
        .await
        .expect("failed to establish remoc channel");
    let conn_handle = tokio::spawn(conn.instrument(tracing::info_span!("remoc_conn")));

    // Create the outer RFnOnce: PAM authentication.
    let auth_fn = remoc::rfn::RFnOnce::new_1(
        |auth_request: AuthRequest| async move {
            tracing::info!(username = %auth_request.username, "PAM authentication starting");

            // PAM authenticate + acct_mgmt + user lookup.
            #[cfg(feature = "pam")]
            let user_info = genmeta_ssh::session::pam::authenticate(
                "sshd",
                &auth_request.username,
                auth_request.credential.password(),
            )
            .await
            .map_err(|e| AuthError::PamFailed {
                reason: Report::from_error(e).to_string(),
            })?;

            // Fallback for non-PAM builds: look up the user without authenticating.
            #[cfg(not(feature = "pam"))]
            let (uid, gid, shell) = {
                let user = nix::unistd::User::from_name(&auth_request.username)
                    .map_err(|e| AuthError::PamFailed {
                        reason: format!("user lookup failed: {e}"),
                    })?
                    .ok_or_else(|| AuthError::UserNotFound {
                        username: auth_request.username.clone(),
                    })?;
                (user.uid.as_raw(), user.gid.as_raw(), user.shell)
            };

            #[cfg(feature = "pam")]
            let (uid, gid, shell) = (user_info.uid, user_info.gid, user_info.shell);

            tracing::info!(uid, gid, "PAM authentication succeeded");

            // Capture user info into the inner closure.
            let username = auth_request.username;

            // Create the inner RFnOnce: drop privileges + run session.
            let start_session_fn: StartSessionFn = remoc::rfn::RFnOnce::new_1(
                move |bootstrap: SessionBootstrap| async move {
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
                    let control_reader =
                        h3x::codec::StreamReader::new(bootstrap.control_reader.into_boxed_quic());
                    let control_writer =
                        h3x::codec::SinkWriter::new(bootstrap.control_writer.into_boxed_quic());

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
                },
            );

            Ok(start_session_fn)
        },
    );

    tx.send(auth_fn)
        .await
        .expect("failed to send AuthenticateFn to parent");

    // Wait for remoc connection to close (rfn tasks run in background).
    let _ = conn_handle.await;
    tracing::info!("child process exiting");
}
