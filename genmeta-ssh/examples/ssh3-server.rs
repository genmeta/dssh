//! SSH3 server (gateway) example.
//!
//! Listens for QUIC connections, handles SSH3 Extended CONNECT requests,
//! and runs session handlers directly.
//!
//! A production server would spawn a privilege-separated child process
//! (ssh3-session) and relay streams via remoc — see the `ssh3-session`
//! example for the child-side flow.
//!
//! Usage: cargo run --example ssh3-server -- <cert.pem> <key.pem> [bind_addr]

use std::sync::Arc;

use genmeta_ssh::{
    Conversation,
    auth::parse_authorization_header,
    constants::SSH_VERSION,
    protocol::Ssh3ProtocolFactory,
    session::dispatcher::{SessionConfig, run_session},
    SSH3_CONNECT_PATH,
};
use h3x::connection::ConnectionBuilder;
use h3x::gm_quic::H3Servers;
use h3x::server::{Request, Response, Router};
use http::{HeaderValue, StatusCode};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <cert.pem> <key.pem> [bind_addr]", args[0]);
        std::process::exit(1);
    }

    let cert_path = &args[1];
    let key_path = &args[2];
    let bind_addr = args.get(3).map(|s| s.as_str()).unwrap_or("0.0.0.0:443");

    let cert_pem = std::fs::read(cert_path).expect("failed to read certificate");
    let key_pem = std::fs::read(key_path).expect("failed to read private key");

    let router = Router::new().connect(SSH3_CONNECT_PATH, handle_ssh3_connect);

    // Register Ssh3ProtocolFactory so each QUIC connection gets an Ssh3Protocol
    // instance that routes bidirectional streams by session ID.
    let builder = ConnectionBuilder::new(Arc::default())
        .protocol(Ssh3ProtocolFactory);

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
            [format!("inet://{bind_addr}")],
            router,
        )
        .await
        .expect("failed to add server");

    tracing::info!(%bind_addr, "SSH3 server listening");
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
