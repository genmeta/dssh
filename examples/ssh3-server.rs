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
//! privileges. Communication uses remoc RPC over a MuxChannel socketpair,
//! with stream data forwarded via FD-passing Unix socketpairs.

use std::convert::Infallible;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use clap::Parser;
use dssh::{
    auth::{AuthCredential, parse_authorization_header},
    constants::{SSH_VERSION, SSH3_CONNECT_PATH},
    conversation::ipc::{IpcManageSessionStreamServerShared, IpcManageStreamAdapter},
    protocol::Ssh3ProtocolFactory,
    session::{AuthRequest, AuthenticateFn, SessionBootstrap},
};
use h3x::connection::{ConnectionBuilder, ConnectionState};
use h3x::dquic::{
    QuicEndpoint,
    binds::BindPattern,
    cert::handy::{ToCertificate, ToPrivateKey},
    identity::Identity,
    server::ServerQuicConfig,
};
use h3x::endpoint::H3Endpoint;
use h3x::hyper::server::TowerService;
use h3x::ipc::transport::MuxChannel;
use h3x::message::stream::MessageStreamError;
use h3x::quic::DynConnection;
use h3x::stream_id::StreamId;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use remoc::prelude::*;
use snafu::Report;
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

    let builder = Arc::new(ConnectionBuilder::new(Arc::default()).protocol(Ssh3ProtocolFactory));
    let identity = Arc::new(Identity {
        name: "localhost".parse().expect("localhost is a valid DNS name"),
        certs: Arc::new(cert_pem.as_slice().to_certificate()),
        key: Arc::new(key_pem.as_slice().to_private_key()),
        ocsp: Arc::new(None),
    });
    let bind: BindPattern = format!("inet://{}", cli.bind)
        .parse()
        .expect("failed to parse bind address");
    let quic = QuicEndpoint::builder()
        .maybe_identity(Some(identity))
        .server(ServerQuicConfig {
            alpns: vec![b"h3".to_vec()],
            ..Default::default()
        })
        .bind(Arc::new(vec![bind]))
        .build()
        .await;
    let mut endpoint = H3Endpoint::builder().quic(quic).builder(builder).build();

    tracing::info!(bind = %cli.bind, "ssh3 server listening");
    if let Err(error) = endpoint.serve(service).await {
        tracing::error!(error = %snafu::Report::from_error(&error), "server stopped");
    }
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
    if request.method() != Method::CONNECT || request.uri().path() != SSH3_CONNECT_PATH {
        return error_response(StatusCode::NOT_FOUND);
    }

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

    let username = match &credential {
        AuthCredential::Basic { username, .. } => username.clone(),
        AuthCredential::Certificate => {
            tracing::warn!("certificate auth not supported in this example");
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
    let connection = request
        .extensions()
        .get::<Arc<ConnectionState<dyn DynConnection>>>()
        .expect("ConnectionState not in extensions")
        .clone();
    let ssh3_proto = connection
        .protocols()
        .get::<dssh::protocol::Ssh3Protocol>()
        .expect("Ssh3ProtocolFactory not registered");
    let handle = match ssh3_proto.register(conversation_id) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "register failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    handle_child_process(
        request,
        handle,
        username,
        credential,
        peer_version,
        conversation_id,
        &session_binary,
    )
    .await
}

/// Child-process session: spawn ssh3-session, PAM auth via remoc RFnOnce.
///
/// Communication uses a MuxChannel socketpair (remoc RPC + FD passing):
/// - remoc channel for RFnOnce exchange and IpcManageSessionStream RPC
/// - FD sideband for control stream and per-stream Unix socketpairs
///
/// PAM authentication happens synchronously before the response is sent.
/// On success, spawns a task that waits for upgrade, sets up FD-based stream
/// serving, and calls the child's StartSessionFn.
async fn handle_child_process(
    mut request: http::Request<BoxBody>,
    handle: dssh::protocol::ConversationHandle,
    username: String,
    credential: dssh::auth::AuthCredential,
    peer_version: String,
    conversation_id: StreamId,
    session_binary: &std::path::Path,
) -> Result<http::Response<BoxBody>, Infallible> {
    let span = tracing::info_span!("child-session", %conversation_id, user = %username);

    // Create MuxChannel socketpair for parent↔child IPC.
    let (parent_mux, child_fd) = match MuxChannel::create_pair() {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to create MuxChannel pair");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Spawn the session child process with the MuxChannel FD on stdin.
    let mut child = match tokio::process::Command::new(session_binary)
        .stdin(child_fd)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to spawn session binary");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Split MuxChannel and establish remoc connection.
    let (sink, stream) = match parent_mux.split() {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to split MuxChannel");
            let _ = child.kill().await;
            return error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let fd_sender = sink.fd_sender();

    let (conn, _tx, mut rx) = match remoc::Connect::framed::<
        _,
        _,
        (),
        AuthenticateFn,
        remoc::codec::Default,
    >(remoc::Cfg::default(), sink, stream)
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to establish remoc channel");
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
        username,
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
            // Takeover the raw ReadStream/WriteStream for the SSH3 control channel.
            let (read_stream, write_stream) = {
                use h3x::hyper::upgrade::{self, ReadStream, WriteStream};

                match (
                    upgrade::take::<ReadStream>(&mut request).await,
                    upgrade::take::<WriteStream>(&mut request).await,
                ) {
                    (Ok(r), Ok(w)) => (r, w),
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::error!(error = %snafu::Report::from_error(&e), "takeover failed");
                        let _ = child.kill().await;
                        return;
                    }
                }
            };

            // Set up control stream via Unix socketpair + FD passing.
            let (ctrl_srv, ctrl_cli) = match std::os::unix::net::UnixStream::pair() {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "control socketpair failed");
                    let _ = child.kill().await;
                    return;
                }
            };
            let ctrl_fd_id = match fd_sender.queue_fds(smallvec::smallvec![ctrl_cli.into()]) {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "queue control FD failed");
                    let _ = child.kill().await;
                    return;
                }
            };
            let ctrl_srv = match tokio::net::UnixStream::from_std(ctrl_srv) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %Report::from_error(&e), "control from_std failed");
                    let _ = child.kill().await;
                    return;
                }
            };
            let (ctrl_read, ctrl_write) = ctrl_srv.into_split();

            // Bridge QUIC CONNECT streams ↔ control stream socketpair.
            tokio::spawn(
                dssh::conversation::ipc::bridge_message_reader_to_unix(
                    Box::pin(read_stream.into_bytes_stream()),
                    ctrl_write,
                )
                .in_current_span(),
            );
            tokio::spawn(
                dssh::conversation::ipc::bridge_unix_to_message_writer(
                    ctrl_read,
                    Box::pin(write_stream.into_bytes_sink()),
                )
                .in_current_span(),
            );

            // Serve the stream management bridge via IPC FD passing.
            let adapter = IpcManageStreamAdapter::new(handle, fd_sender);
            let (ms, mc) = IpcManageSessionStreamServerShared::new(Arc::new(adapter), 1);
            tokio::spawn(
                async move {
                    let _ = ms.serve(true).await;
                }
                .in_current_span(),
            );

            let bootstrap = SessionBootstrap {
                manage_stream: mc,
                control_fd_id: ctrl_fd_id,
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
