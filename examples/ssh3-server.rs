//! SSH3 server (gateway) example.
//!
//! Listens for QUIC connections, handles SSH3 Extended CONNECT requests,
//! and dispatches sessions via privilege-separated child processes.
//!
//! Uses tower service + h3x upgrade pattern: the handler returns an HTTP
//! response, then a spawned task obtains the underlying streams via the
//! upgrade/takeover mechanism for the SSH3 session.
//!
//! Each session spawns a child process (`--session-binary <path>`) that
//! performs PAM authentication and runs the session after dropping
//! privileges. Communication uses remoc RFnOnce over stdin/stdout.

use std::convert::Infallible;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use clap::Parser;
use genmeta_ssh::{
    auth::parse_authorization_header,
    client::SSH3_CONNECT_PATH,
    constants::SSH_VERSION,
    conversation::remoc::{ManageStreamBridge, RemoteManageStreamServerShared},
    protocol::Ssh3ProtocolFactory,
    session::{AuthRequest, AuthenticateFn, SessionBootstrap},
};
use h3x::connection::ConnectionBuilder;
use h3x::gm_quic::H3Servers;
use h3x::hyper::server::TowerService;
use h3x::message::stream::MessageStreamError;
use h3x::protocol::Protocols;
use h3x::remoc::message::{ReadMessageStreamServer, WriteMessageStreamServer};
use h3x::server::Router;
use h3x::stream_id::StreamId;
use http::StatusCode;
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use remoc::prelude::*;
use tracing::Instrument;

type BoxBody = UnsyncBoxBody<Bytes, MessageStreamError>;

fn empty_body() -> BoxBody {
    UnsyncBoxBody::new(Empty::new().map_err(|n: Infallible| match n {}))
}

#[derive(Parser)]
#[command(about = "SSH3 server example")]
struct Cli {
    /// Path to TLS certificate (PEM)
    cert: String,

    /// Path to TLS private key (PEM)
    key: String,

    /// Bind address
    #[arg(short, long, default_value = "0.0.0.0:443")]
    bind: String,

    /// Path to session binary for privilege-separated mode.
    /// Each session spawns a child process that handles PAM authentication
    /// and runs the session after dropping privileges.
    #[arg(long)]
    session_binary: PathBuf,
}

/// Tower service that handles SSH3 Extended CONNECT requests.
///
/// Wrapped by [`TowerService`] to bridge between h3x's server framework
/// and the tower service interface.
#[derive(Clone)]
struct Ssh3ConnectService {
    session_binary: PathBuf,
}

impl tower_service::Service<http::Request<BoxBody>> for Ssh3ConnectService {
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<BoxBody>) -> Self::Future {
        let session_binary = self.session_binary.clone();
        Box::pin(handle_ssh3_connect(request, session_binary))
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let cert_pem = std::fs::read(&cli.cert).expect("failed to read certificate");
    let key_pem = std::fs::read(&cli.key).expect("failed to read private key");

    let service = TowerService(Ssh3ConnectService {
        session_binary: cli.session_binary,
    });

    let router = Router::new().connect(SSH3_CONNECT_PATH, service);

    let builder = ConnectionBuilder::new(Arc::default()).protocol(Ssh3ProtocolFactory);

    let mut servers: H3Servers<_> = H3Servers::builder()
        .without_client_cert_verifier()
        .expect("failed to configure TLS")
        .with_builder(Arc::new(builder))
        .listen()
        .expect("failed to create listener");

    servers
        .add_server(
            "localhost",
            cert_pem.as_slice(),
            key_pem.as_slice(),
            None::<Vec<u8>>,
            [format!("inet://{}", cli.bind)],
            router,
        )
        .await
        .expect("failed to add server");

    tracing::info!(bind = %cli.bind, "SSH3 server listening");
    let err = servers.run().await;
    tracing::error!(error = %err, "server stopped");
}

fn error_response(status: StatusCode) -> Result<http::Response<BoxBody>, Infallible> {
    Ok(http::Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap())
}

fn ok_response() -> Result<http::Response<BoxBody>, Infallible> {
    Ok(http::Response::builder()
        .status(StatusCode::OK)
        .header("ssh-version", SSH_VERSION)
        .body(empty_body())
        .unwrap())
}

async fn handle_ssh3_connect(
    request: http::Request<BoxBody>,
    session_binary: PathBuf,
) -> Result<http::Response<BoxBody>, Infallible> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let credential = match parse_authorization_header(auth_header) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %snafu::Report::from_error(&e), "auth parse failed");
            return error_response(StatusCode::UNAUTHORIZED);
        }
    };

    let peer_version = match request
        .headers()
        .get("ssh-version")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) if v == SSH_VERSION => v.to_owned(),
        _ => return error_response(StatusCode::BAD_REQUEST),
    };

    let conversation_id = *request
        .extensions()
        .get::<StreamId>()
        .expect("StreamId not in extensions");
    let protocols = request
        .extensions()
        .get::<Arc<Protocols>>()
        .expect("Protocols not in extensions")
        .clone();
    let ssh3_proto = protocols
        .get::<genmeta_ssh::protocol::Ssh3Protocol>()
        .expect("Ssh3ProtocolFactory not registered");
    let handle = match ssh3_proto.register(conversation_id) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %snafu::Report::from_error(&e), "register failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    handle_child_process(
        request,
        handle,
        credential,
        peer_version,
        conversation_id,
        &session_binary,
    )
    .await
}

/// Child-process session: spawn ssh3-session, PAM auth via remoc RFnOnce.
///
/// PAM authentication happens synchronously before the response is sent.
/// On success, spawns a task that waits for upgrade, sets up remoc stream
/// serving, and calls the child's StartSessionFn.
async fn handle_child_process(
    request: http::Request<BoxBody>,
    handle: genmeta_ssh::protocol::ConversationHandle,
    credential: genmeta_ssh::auth::AuthCredential,
    peer_version: String,
    conversation_id: StreamId,
    session_binary: &std::path::Path,
) -> Result<http::Response<BoxBody>, Infallible> {
    let span =
        tracing::info_span!("child-session", %conversation_id, user = %credential.username());

    // Spawn the session child process.
    let mut child = match tokio::process::Command::new(session_binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to spawn session binary");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();

    // Establish remoc channel: we receive AuthenticateFn from the child.
    let (conn, _tx, mut rx) =
        match remoc::Connect::io::<_, _, (), AuthenticateFn, remoc::codec::Default>(
            remoc::Cfg::default(),
            child_stdout,
            child_stdin,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "failed to establish remoc channel with child");
                let _ = child.kill().await;
                return error_response(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
    let conn_handle = tokio::spawn(conn.instrument(span.clone()));

    // Receive the AuthenticateFn from the child.
    let auth_fn: AuthenticateFn = match rx.recv().await {
        Ok(Some(f)) => f,
        _ => {
            tracing::error!("child did not send AuthenticateFn");
            let _ = child.kill().await;
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Call the child's PAM authentication.
    let auth_request = AuthRequest {
        username: credential.username().to_owned(),
        credential,
    };

    let start_session_fn = match auth_fn.call(auth_request).await {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %snafu::Report::from_error(&e), "authentication failed");
            let _ = child.kill().await;
            return error_response(StatusCode::UNAUTHORIZED);
        }
    };

    // Auth succeeded — spawn session task. The response is returned below,
    // and h3x sends it on the wire. The spawned task waits for the upgrade
    // to complete (streams become available after the response is sent).
    tokio::spawn(
        async move {
            // Takeover the raw ReadStream/WriteStream individually so we can
            // obtain bytes_stream/bytes_sink for remoc message-level serving.
            let (read_stream, write_stream) = {
                use h3x::hyper::upgrade::{TakeoverError, TakeoverSlot, ReadStream, WriteStream};

                let read_pending = request
                    .extensions()
                    .get::<TakeoverSlot<ReadStream>>()
                    .ok_or(TakeoverError::Aborted)
                    .and_then(|s| s.take());
                let write_pending = request
                    .extensions()
                    .get::<TakeoverSlot<WriteStream>>()
                    .ok_or(TakeoverError::Aborted)
                    .and_then(|s| s.take());

                match (read_pending, write_pending) {
                    (Ok(rp), Ok(wp)) => match (rp.wait().await, wp.wait().await) {
                        (Ok(r), Ok(w)) => (r, w),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!(error = %snafu::Report::from_error(&e), "takeover failed");
                            let _ = child.kill().await;
                            return;
                        }
                    },
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::error!(error = %snafu::Report::from_error(&e), "takeover failed");
                        let _ = child.kill().await;
                        return;
                    }
                }
            };

            // Serve control streams via remoc so the child can use them.
            let (rs, rc) =
                ReadMessageStreamServer::new(Box::pin(read_stream.into_bytes_stream()), 1);
            tokio::spawn(
                async move {
                    let _ = rs.serve().await;
                }
                .in_current_span(),
            );

            let (ws, wc) =
                WriteMessageStreamServer::new(Box::pin(write_stream.into_bytes_sink()), 1);
            tokio::spawn(
                async move {
                    let _ = ws.serve().await;
                }
                .in_current_span(),
            );

            // Serve the stream management bridge via remoc.
            let bridge = ManageStreamBridge::new(handle);
            let (ms, mc) = RemoteManageStreamServerShared::new(Arc::new(bridge), 1);
            tokio::spawn(
                async move {
                    let _ = ms.serve(true).await;
                }
                .in_current_span(),
            );

            let bootstrap = SessionBootstrap {
                manage_stream: mc,
                control_reader: rc,
                control_writer: wc,
                conversation_id,
                peer_version,
            };

            tracing::info!(%conversation_id, "calling StartSessionFn in child");

            match start_session_fn.call(bootstrap).await {
                Ok(()) => tracing::info!(%conversation_id, "child session completed"),
                Err(e) => tracing::error!(
                    error = %snafu::Report::from_error(&e),
                    "child session failed"
                ),
            }

            // Wait for the child process and remoc connection to finish.
            let _ = child.wait().await;
            let _ = conn_handle.await;
            tracing::info!(%conversation_id, "session ended (child-process)");
        }
        .instrument(span),
    );

    ok_response()
}
