//! SSH3 server (gateway) example.
//!
//! Listens for QUIC connections, handles SSH3 Extended CONNECT requests,
//! spawns privilege-separated child processes (ssh3-session), and routes
//! streams via [`Ssh3Protocol`].
//!
//! Usage: cargo run --example ssh3-server -- <cert.pem> <key.pem> [bind_addr]

use genmeta_ssh::{
    auth::parse_authorization_header,
    SSH3_CONNECT_PATH,
};
use h3x::gm_quic::H3Servers;
use h3x::server::{Request, Response, Router};

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

    let mut servers: H3Servers<_> = H3Servers::builder()
        .without_client_cert_verifier()
        .expect("failed to configure TLS")
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

async fn handle_ssh3_connect(req: &mut Request, _res: &mut Response) {
    // Parse auth header.
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let _credential = parse_authorization_header(auth_header);

    // TODO: complete the server flow:
    // 1. Negotiate SSH version from request headers
    // 2. Spawn ssh3-session child process
    // 3. Send ChildBootstrap via remoc over child's stdin/stdout
    // 4. Register Ssh3Protocol for this connection
    // 5. Route streams to the child's Conversation via ConversationHandle

    tracing::info!("SSH3 connection request received");
}
