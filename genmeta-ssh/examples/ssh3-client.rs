//! SSH3 client example.
//!
//! Connects to an SSH3 server, opens a session channel, executes a command
//! (or starts an interactive shell), and relays stdin/stdout.
//!
//! Usage: cargo run --example ssh3-client -- <user:pass@host:port> [command...]

use genmeta_ssh::{
    client::Ssh3Client,
    session::client::ClientSession,
    SessionChannelOpen, SshChannel,
    DEFAULT_MAX_MESSAGE_SIZE,
};
use h3x::gm_quic::H3Client;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <user:pass@host:port> [command...]", args[0]);
        std::process::exit(1);
    }

    let authority_str = &args[1];
    let command: Option<String> = if args.len() > 2 {
        Some(args[2..].join(" "))
    } else {
        None
    };

    // Build h3x QUIC client (no server cert verification for demo).
    let client: H3Client = H3Client::builder()
        .without_server_cert_verification()
        .without_identity()
        .expect("failed to configure TLS")
        .build();

    // Create SSH3 client with basic auth.
    let ssh3_client = Ssh3Client::with_basic_auth(authority_str, "user", "pass");

    // Connect → Conversation.
    let conversation = ssh3_client
        .connect(&client)
        .await
        .expect("SSH3 connect failed");

    tracing::info!("connected, peer version: {}", conversation.peer_version());

    // Open a session channel.
    let (reader, writer) = conversation
        .open_channel(&SessionChannelOpen, DEFAULT_MAX_MESSAGE_SIZE)
        .await
        .expect("failed to open session channel");

    let channel = SshChannel::new(reader, writer);
    let mut session = ClientSession::new(channel);

    // Send exec or shell request.
    match command {
        Some(cmd) => {
            session.exec(cmd.as_bytes()).await.expect("exec request failed");
        }
        None => {
            session.shell().await.expect("shell request failed");
        }
    }

    // TODO: relay stdin/stdout/stderr until session ends.
    // This requires reading SessionEvents from the channel and
    // forwarding data between the terminal and the SSH channel.

    tracing::info!("session complete");
}
