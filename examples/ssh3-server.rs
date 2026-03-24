//! SSH3 server (gateway) example.
//!
//! Listens for QUIC connections, handles SSH3 Extended CONNECT requests,
//! and runs session handlers directly.
//!
//! A production server would spawn a privilege-separated child process
//! (ssh3-session) and relay streams via remoc — see the `ssh3-session`
//! example for the child-side flow.

use std::sync::Arc;

use clap::Parser;
use genmeta_ssh::{
    client::SSH3_CONNECT_PATH,
    constants::SSH_VERSION,
    conversation::Conversation,
    auth::parse_authorization_header,
    protocol::Ssh3ProtocolFactory,
    session::dispatcher::{SessionConfig, run_session},
};
use h3x::connection::ConnectionBuilder;
use h3x::gm_quic::H3Servers;
use h3x::server::{Request, Response, Router};
use http::{HeaderValue, StatusCode};

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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let cert_pem = std::fs::read(&cli.cert).expect("failed to read certificate");
    let key_pem = std::fs::read(&cli.key).expect("failed to read private key");

    let router = Router::new().connect(SSH3_CONNECT_PATH, handle_ssh3_connect);

    // Register Ssh3ProtocolFactory so each QUIC connection gets an Ssh3Protocol
    // instance that routes bidirectional streams by session ID.
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

async fn handle_ssh3_connect(req: &mut Request, res: &mut Response) {
    // Parse and validate auth credential.
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let _credential = match parse_authorization_header(auth_header) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %snafu::Report::from_error(&e), "auth parse failed");
            res.set_status(StatusCode::UNAUTHORIZED);
            return;
        }
    };

    // Validate SSH version.
    let peer_version = match req.header("ssh-version").and_then(|v| v.to_str().ok()) {
        Some(v) if v == SSH_VERSION => v.to_owned(),
        _ => {
            res.set_status(StatusCode::BAD_REQUEST);
            return;
        }
    };

    let conversation_id = res.stream_id();

    // Retrieve the per-connection Ssh3Protocol to register this session.
    let ssh3_proto = res
        .protocols()
        .get::<genmeta_ssh::protocol::Ssh3Protocol>()
        .expect("Ssh3ProtocolFactory not registered");
    let handle = match ssh3_proto.register(conversation_id) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %snafu::Report::from_error(&e), "register failed");
            res.set_status(StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }
    };

    // Respond 200 — the request/response streams become the control tunnel.
    res.set_status(StatusCode::OK);
    res.set_header("ssh-version", HeaderValue::from_static(SSH_VERSION));

    // Take the HTTP/3 message streams and convert to AsyncRead/AsyncWrite.
    let control_reader = req.read_stream().take().into_box_reader();
    let control_writer = res.write_stream().take().into_box_writer();

    let conversation = Arc::new(Conversation::new(
        conversation_id,
        peer_version,
        control_reader,
        control_writer,
        handle,
    ));

    let config = SessionConfig {
        shell: "/bin/sh".into(),
        ..Default::default()
    };

    tracing::info!(%conversation_id, "session starting");
    run_session(conversation, config).await;
    tracing::info!(%conversation_id, "session ended");
}
