//! SSH3 session child process example.
//!
//! Spawned by the SSH3 server (ssh3-server example) for each connection.
//! Communicates with the parent via remoc RPC over a MuxChannel socketpair
//! received on stdin (FD 0).
//!
//! Flow:
//! 1. Send `AuthenticateFn` to parent over remoc
//! 2. Parent calls it with `AuthRequest` → child runs PAM authentication
//! 3. On success, return `StartSessionFn` to parent
//! 4. Parent calls it with `SessionBootstrap` → child drops privileges
//!    and runs the session dispatcher
//!
//! Stream data travels through FD-passed Unix socketpairs, not through
//! remoc serialization.

use std::sync::Arc;

use dssh::{
    auth::AuthCredential,
    conversation::Conversation,
    session::{
        AuthError, AuthRequest, SessionBootstrap, SessionRunError, StartSessionFn, UserInfo,
        dispatcher::{SessionConfig, run_session},
        privilege::drop_privileges,
    },
};
use h3x::ipc::transport::MuxChannel;
use snafu::Report;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    // Recover the MuxChannel FD from stdin (passed by the parent process).
    let mux_fd = {
        use std::os::fd::FromRawFd;
        // SAFETY: the parent process passed the socketpair FD as our stdin
        // (FD 0) via tokio::process::Command.
        unsafe { std::os::fd::OwnedFd::from_raw_fd(0) }
    };

    let mux = MuxChannel::from_fd(mux_fd).expect("failed to create MuxChannel from stdin");
    let (sink, stream) = mux.split().expect("failed to split MuxChannel");

    // Capture FD registry before remoc consumes the stream.
    let fd_registry = stream.fd_registry();

    // Establish remoc channel over MuxSink/MuxStream.
    let (conn, mut tx, _rx) =
        remoc::Connect::framed::<_, _, dssh::session::AuthenticateFn, (), remoc::codec::Default>(
            remoc::Cfg::default(),
            sink,
            stream,
        )
        .await
        .expect("failed to establish remoc channel");
    let conn_handle = AbortOnDropHandle::new(tokio::spawn(
        conn.instrument(tracing::info_span!("remoc_conn")),
    ));

    // Create the outer RFnOnce: authentication.
    let auth_fn = remoc::rfn::RFnOnce::new_1(|auth_request: AuthRequest| async move {
        tracing::info!(
            username = %auth_request.username,
            credential = %auth_request.credential,
            "authentication starting"
        );

        let user_info: UserInfo = match &auth_request.credential {
            AuthCredential::Basic { .. } => {
                return Err(AuthError::PamFailed {
                    reason: "password authentication is no longer supported".to_owned(),
                });
            }
            #[cfg(feature = "pam")]
            AuthCredential::Certificate => {
                dssh::session::pam::open_session("sshd", &auth_request.username)
                    .await
                    .map_err(|e| AuthError::PamFailed {
                        reason: Report::from_error(e).to_string(),
                    })?
            }
            #[cfg(not(feature = "pam"))]
            AuthCredential::Certificate => {
                let user_info = dssh::session::lookup_user(&auth_request.username)
                    .await
                    .map_err(|e| AuthError::PamFailed {
                        reason: Report::from_error(e).to_string(),
                    })?;
                if let Err(msg) = dssh::session::check_nologin(user_info.uid) {
                    return Err(AuthError::PamFailed { reason: msg });
                }
                user_info
            }
        };

        tracing::info!(
            uid = user_info.uid,
            gid = user_info.gid,
            "authentication succeeded"
        );

        let username = auth_request.username;

        // Create the inner RFnOnce: drop privileges + run session.
        let start_session_fn: StartSessionFn =
            remoc::rfn::RFnOnce::new_1(move |bootstrap: SessionBootstrap| async move {
                tracing::info!(%username, "starting session");

                if nix::unistd::getuid().is_root() {
                    drop_privileges(user_info.uid, user_info.gid, &username).map_err(|e| {
                        SessionRunError::DropPrivileges {
                            reason: Report::from_error(e).to_string(),
                        }
                    })?;
                    tracing::info!(
                        uid = user_info.uid,
                        gid = user_info.gid,
                        "privileges dropped"
                    );
                }

                // Resolve control stream from FD registry.
                let fds = fd_registry
                    .wait_fds(bootstrap.control_fd_id)
                    .await
                    .map_err(|e| SessionRunError::ConversationBuild {
                        reason: Report::from_error(e).to_string(),
                    })?;
                let ctrl_fd =
                    fds.into_iter()
                        .next()
                        .ok_or_else(|| SessionRunError::ConversationBuild {
                            reason: "expected 1 FD for control stream, got 0".into(),
                        })?;
                let ctrl_unix =
                    tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(ctrl_fd))
                        .map_err(|e| SessionRunError::ConversationBuild {
                            reason: format!("failed to convert control FD to tokio stream: {e}"),
                        })?;
                let (control_reader, control_writer) = ctrl_unix.into_split();

                // Create IPC manage stream handle.
                let manage_stream = dssh::conversation::ipc::IpcManageStreamHandle::new(
                    bootstrap.manage_stream,
                    fd_registry,
                );

                let conversation = Arc::new(Conversation::new(
                    bootstrap.conversation_id,
                    bootstrap.peer_version,
                    control_reader,
                    control_writer,
                    manage_stream,
                ));

                let config = SessionConfig {
                    user: user_info,
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

    let _ = conn_handle.await;
    tracing::info!("ssh session process exiting");
}
