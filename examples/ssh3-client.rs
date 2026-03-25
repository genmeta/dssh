//! SSH3 client example.
//!
//! Connects to an SSH3 server, opens a session channel, executes a command
//! (or starts an interactive shell), and relays stdin/stdout.
//!
//! Supports OpenSSH-compatible port forwarding:
//! - `-L` — local forwarding (TCP and Unix socket)
//! - `-R` — remote forwarding (TCP and Unix socket)
//! - `-D` — dynamic SOCKS forwarding

use std::pin::Pin;
use std::sync::Arc;

use clap::Parser;
use genmeta_ssh::{
    client::SSH3_CONNECT_PATH,
    client::encode_basic_auth,
    constants::{DEFAULT_MAX_MESSAGE_SIZE, SSH_VERSION},
    conversation::{Conversation, channel::SshChannel},
    forward::{
        SessionChannelOpen,
        client::{RemoteForwardEstablished, accept_forwarded_channels},
        spec::{DynamicForward, LocalForward, RemoteForward},
    },
    protocol::{ConversationHandle, Ssh3Protocol},
    session::client::ClientSession,
};
use h3x::gm_quic::H3Client;
use h3x::qpack::field::Protocol;
use h3x::quic::GetStreamIdExt;
use h3x::stream_id::StreamId;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::{ResultExt, Whatever, ensure_whatever};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Instrument;

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(about = "SSH3 client example")]
struct Cli {
    /// Server authority (host:port)
    authority: String,

    /// Username for basic auth
    #[arg(short, long, default_value = "user")]
    user: String,

    /// Password for basic auth
    #[arg(short, long, default_value = "pass")]
    password: String,

    /// Local port forwarding (OpenSSH-compatible syntax).
    ///
    /// Examples:
    ///   -L 8080:remote:80            TCP localhost:8080 → remote:80
    ///   -L 0.0.0.0:8080:remote:80    TCP all-interfaces:8080 → remote:80
    ///   -L 8080:/tmp/remote.sock     TCP localhost:8080 → Unix socket
    ///   -L /tmp/local.sock:remote:80 Unix socket → TCP remote:80
    #[arg(short = 'L', value_name = "SPEC")]
    local_forward: Vec<LocalForward>,

    /// Remote port forwarding (OpenSSH-compatible syntax).
    ///
    /// Examples:
    ///   -R 8080:localhost:80             TCP *:8080 → localhost:80
    ///   -R 0.0.0.0:8080:localhost:80     TCP all-interfaces:8080 → localhost:80
    ///   -R 8080                           TCP *:8080 (listen-only)
    ///   -R /tmp/remote.sock:localhost:80  Unix socket → TCP localhost:80
    #[arg(short = 'R', value_name = "SPEC")]
    remote_forward: Vec<RemoteForward>,

    /// Dynamic SOCKS5 forwarding (OpenSSH-compatible syntax).
    ///
    /// Examples:
    ///   -D 1080           SOCKS5 on localhost:1080
    ///   -D 0.0.0.0:1080   SOCKS5 on all interfaces
    #[arg(short = 'D', value_name = "SPEC")]
    dynamic_forward: Vec<DynamicForward>,

    /// Command to execute (omit for interactive shell)
    command: Vec<String>,
}

// ============================================================================
// Connection
// ============================================================================

/// Connect to an SSH3 server via Extended CONNECT.
async fn connect(
    authority: &str,
    auth_header: HeaderValue,
    client: &H3Client,
) -> Result<Conversation<ConversationHandle>, Whatever> {
    let authority_parsed: http::uri::Authority =
        authority.parse().whatever_context("invalid authority")?;

    let connection = client
        .connect(authority_parsed.clone())
        .await
        .whatever_context("failed to establish QUIC connection")?;

    let uri: http::Uri = format!("https://{authority_parsed}{SSH3_CONNECT_PATH}")
        .parse()
        .whatever_context("invalid URI")?;

    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("ssh-version", SSH_VERSION)
        .header(http::header::AUTHORIZATION, auth_header)
        .extension(Protocol::new("ssh3"))
        .body(Empty::<bytes::Bytes>::new())
        .whatever_context("failed to build HTTP request")?;

    let (mut read_stream, mut write_stream) = connection
        .initial_message_stream()
        .await
        .whatever_context("failed to open initial message stream")?;

    let conversation_id = write_stream
        .stream_id()
        .await
        .whatever_context("failed to get stream ID")?
        .into_inner();

    write_stream
        .send_hyper_request(request)
        .await
        .whatever_context("failed to send Extended CONNECT request")?;

    let mut response = read_stream
        .read_hyper_response_parts()
        .await
        .whatever_context("failed to read HTTP response")?;

    while response.status.is_informational() {
        response = read_stream
            .read_hyper_response_parts()
            .await
            .whatever_context("failed to read HTTP response")?;
    }

    ensure_whatever!(
        response.status != StatusCode::UNAUTHORIZED,
        "authentication failed (HTTP 401)"
    );
    ensure_whatever!(
        response.status == StatusCode::OK,
        "unexpected HTTP status: {}",
        response.status
    );

    let server_version_header = response.headers.get("ssh-version");
    ensure_whatever!(
        server_version_header.is_some(),
        "missing ssh-version response header"
    );
    let server_version = server_version_header
        .unwrap()
        .to_str()
        .whatever_context("invalid ssh-version header value")?
        .to_owned();

    ensure_whatever!(
        server_version == SSH_VERSION,
        "server offered unsupported version: {server_version}"
    );

    tracing::info!(
        %authority,
        conversation_id,
        version = %server_version,
        "SSH3 connection established"
    );

    let session_id = StreamId::try_from(conversation_id).unwrap();

    // Try to use the connection's Ssh3Protocol (registered via Ssh3ProtocolFactory).
    // This is required for accepting incoming channels (remote forwarding).
    // Falls back to a standalone protocol if the factory wasn't registered.
    let handle = if let Some(proto) = connection.protocol::<Ssh3Protocol>() {
        proto
            .register(session_id)
            .whatever_context("failed to register conversation")?
    } else {
        let conn = connection.clone();
        let protocol = Ssh3Protocol::new(move || {
            let conn = conn.clone();
            Box::pin(async move {
                use h3x::codec::BoxReadStream;
                use h3x::codec::BoxWriteStream;
                let (reader, writer) = conn.open_bi().await?;
                Ok((
                    Box::pin(reader) as BoxReadStream,
                    Box::pin(writer) as BoxWriteStream,
                ))
            })
        });
        protocol
            .register(session_id)
            .whatever_context("failed to register conversation")?
    };

    let control_reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(read_stream.into_box_reader());
    let control_writer: Pin<Box<dyn AsyncWrite + Send>> = Box::pin(write_stream.into_box_writer());

    Ok(Conversation::new(
        session_id,
        server_version,
        control_reader,
        control_writer,
        handle,
    ))
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let command: Option<String> = if cli.command.is_empty() {
        None
    } else {
        Some(cli.command.join(" "))
    };

    let has_remote_forwards = !cli.remote_forward.is_empty();
    let client: H3Client = {
        let mut builder = H3Client::builder()
            .without_server_cert_verification()
            .without_identity()
            .expect("failed to configure TLS");

        // Register Ssh3Protocol so the client can accept incoming channels
        // from the server (required for remote forwarding -R).
        if has_remote_forwards {
            use h3x::connection::ConnectionBuilder;
            let conn_builder = ConnectionBuilder::new(Arc::default())
                .protocol(genmeta_ssh::protocol::Ssh3ProtocolFactory);
            builder = builder.with_builder(Arc::new(conn_builder));
        }

        builder.build()
    };

    let auth_header = encode_basic_auth(&cli.user, &cli.password);
    let conversation = Arc::new(
        connect(&cli.authority, auth_header, &client)
            .await
            .expect("SSH3 connect failed"),
    );

    tracing::info!("connected, peer version: {}", conversation.peer_version());

    // Start local forward listeners (-L).
    let mut forward_tasks = tokio::task::JoinSet::new();
    for spec in cli.local_forward {
        let conv = conversation.clone();
        let label = spec.to_string();
        forward_tasks.spawn(async move {
            let Err(e) = spec.run(conv).instrument(tracing::info_span!("local_forward", %label)).await;
            tracing::error!(error = %snafu::Report::from_error(&e), "local forward failed");
        });
    }

    // Request remote forwards (-R).
    let mut remote_mappings: Vec<RemoteForwardEstablished> = Vec::new();
    for spec in &cli.remote_forward {
        let established = spec
            .request(&conversation)
            .await
            .unwrap_or_else(|e| panic!("remote forward request failed: {e}"));
        remote_mappings.push(established);
    }

    // Spawn channel acceptor for remote forwards (-R).
    if !remote_mappings.is_empty() {
        let conv = conversation.clone();
        forward_tasks.spawn(
            accept_forwarded_channels(conv, remote_mappings)
                .instrument(tracing::info_span!("channel_acceptor")),
        );
    }

    // Dynamic forwards (-D).
    if !cli.dynamic_forward.is_empty() {
        tracing::error!("dynamic SOCKS5 forwarding (-D) is not yet implemented");
        std::process::exit(1);
    }

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
            session
                .exec(cmd.as_bytes())
                .await
                .expect("exec request failed");
        }
        None => {
            session.shell().await.expect("shell request failed");
        }
    }

    // Relay I/O: stdin → channel, channel events → stdout/stderr.
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let stderr = tokio::io::stderr();

    let exit = session
        .run(stdin, stdout, stderr)
        .await
        .expect("session IO relay failed");

    let exit_code = match exit {
        Some(genmeta_ssh::session::client::ExitResult::Status(code)) => code,
        Some(genmeta_ssh::session::client::ExitResult::Signal { signal_name, .. }) => {
            tracing::info!(%signal_name, "process killed by signal");
            128
        }
        None => 1,
    };

    // Forward tasks are dropped (aborted) when we exit.
    std::process::exit(exit_code as i32);
}
