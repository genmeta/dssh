//! SSH3 client example.
//!
//! Connects to an SSH3 server, opens a session channel, executes a command
//! (or starts an interactive shell), and relays stdin/stdout.
//!
//! Supports TCP port forwarding:
//! - `-L [bind_addr:]port:host:hostport` — local forwarding
//! - `-R [bind_addr:]port:host:hostport` — remote forwarding

use std::pin::Pin;
use std::sync::Arc;

use clap::Parser;
use genmeta_ssh::{
    client::SSH3_CONNECT_PATH,
    client::encode_basic_auth,
    codec::SshString,
    constants::{DEFAULT_MAX_MESSAGE_SIZE, SSH_VERSION},
    conversation::{Conversation, channel::SshChannel},
    forward::{
        DirectTcpip, ForwardedTcpip, SessionChannelOpen, TcpipForwardGlobalRequest,
        TcpipForwardRequest, relay,
    },
    protocol::{ConversationHandle, Ssh3Protocol},
    session::client::ClientSession,
};
use h3x::gm_quic::H3Client;
use h3x::qpack::field::Protocol;
use h3x::quic::GetStreamIdExt;
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::{ResultExt, Whatever, ensure_whatever};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::Instrument;

/// A parsed port forwarding specification.
///
/// Syntax: `[bind_address:]port:host:hostport`
#[derive(Debug, Clone)]
struct ForwardSpec {
    bind_addr: String,
    bind_port: u16,
    dest_host: String,
    dest_port: u16,
}

impl std::str::FromStr for ForwardSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // OpenSSH-compatible syntax: [bind_address:]port:host:hostport
        let parts: Vec<&str> = s.split(':').collect();
        match parts.len() {
            // port:host:hostport (bind to localhost)
            3 => Ok(ForwardSpec {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: parts[0].parse().map_err(|e| format!("invalid bind port: {e}"))?,
                dest_host: parts[1].to_string(),
                dest_port: parts[2].parse().map_err(|e| format!("invalid dest port: {e}"))?,
            }),
            // bind_address:port:host:hostport
            4 => Ok(ForwardSpec {
                bind_addr: parts[0].to_string(),
                bind_port: parts[1].parse().map_err(|e| format!("invalid bind port: {e}"))?,
                dest_host: parts[2].to_string(),
                dest_port: parts[3].parse().map_err(|e| format!("invalid dest port: {e}"))?,
            }),
            _ => Err(format!(
                "invalid forward spec '{s}': expected [bind_addr:]port:host:hostport"
            )),
        }
    }
}

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

    /// Local port forwarding: [bind_addr:]port:host:hostport
    #[arg(short = 'L', num_args = 1)]
    local_forward: Vec<String>,

    /// Remote port forwarding: [bind_addr:]port:host:hostport
    #[arg(short = 'R', num_args = 1)]
    remote_forward: Vec<String>,

    /// Command to execute (omit for interactive shell)
    command: Vec<String>,
}

/// Connect to an SSH3 server via Extended CONNECT.
async fn connect(
    authority: &str,
    auth_header: HeaderValue,
    client: &H3Client,
) -> Result<Conversation<ConversationHandle>, Whatever> {
    let authority_parsed: http::uri::Authority = authority
        .parse()
        .whatever_context("invalid authority")?;

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
        "unexpected HTTP status: {}", response.status
    );

    let server_version_header = response
        .headers
        .get("ssh-version");
    ensure_whatever!(server_version_header.is_some(), "missing ssh-version response header");
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

    let control_reader: Pin<Box<dyn AsyncRead + Send>> =
        Box::pin(read_stream.into_box_reader());
    let control_writer: Pin<Box<dyn AsyncWrite + Send>> =
        Box::pin(write_stream.into_box_writer());

    Ok(Conversation::new(
        session_id,
        server_version,
        control_reader,
        control_writer,
        handle,
    ))
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let cli = Cli::parse();

    let command: Option<String> = if cli.command.is_empty() {
        None
    } else {
        Some(cli.command.join(" "))
    };

    // Parse forward specifications early to fail fast on invalid syntax.
    let local_forwards: Vec<ForwardSpec> = cli
        .local_forward
        .iter()
        .map(|s| s.parse().expect("invalid -L forward spec"))
        .collect();
    let remote_forwards: Vec<ForwardSpec> = cli
        .remote_forward
        .iter()
        .map(|s| s.parse().expect("invalid -R forward spec"))
        .collect();

    let has_remote_forwards = !remote_forwards.is_empty();
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
    for spec in local_forwards {
        let conv = conversation.clone();
        forward_tasks.spawn(
            run_local_forward(conv, spec.clone())
                .instrument(tracing::info_span!(
                    "local_forward",
                    bind = %format!("{}:{}", spec.bind_addr, spec.bind_port),
                    dest = %format!("{}:{}", spec.dest_host, spec.dest_port),
                )),
        );
    }

    // Request remote forwards (-R).
    // Build a mapping from (server_bind_addr, allocated_port) → local target
    // so the channel acceptor knows where to connect for incoming channels.
    let mut remote_targets: Vec<(String, u16, String, u16)> = Vec::new();
    for spec in &remote_forwards {
        let request = TcpipForwardGlobalRequest {
            payload: TcpipForwardRequest {
                bind_address: SshString::from(spec.bind_addr.clone()),
                bind_port: VarInt::from(spec.bind_port as u32),
            },
        };
        let reply = conversation
            .request(&request)
            .await
            .unwrap_or_else(|e| panic!("tcpip-forward request failed: {e}"));
        let allocated_port = reply.allocated_port.into_inner() as u16;
        tracing::info!(
            bind = %format!("{}:{}", spec.bind_addr, allocated_port),
            dest = %format!("{}:{}", spec.dest_host, spec.dest_port),
            "remote forward established"
        );
        remote_targets.push((
            spec.bind_addr.clone(),
            allocated_port,
            spec.dest_host.clone(),
            spec.dest_port,
        ));
    }

    // Spawn channel acceptor for remote forwards (-R).
    if !remote_targets.is_empty() {
        let conv = conversation.clone();
        forward_tasks.spawn(
            run_channel_acceptor(conv, remote_targets)
                .instrument(tracing::info_span!("channel_acceptor")),
        );
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

/// Run a local forward listener (-L).
///
/// Binds a TCP listener on `spec.bind_addr:spec.bind_port`. For each accepted
/// connection, opens a `direct-tcpip` channel to `spec.dest_host:spec.dest_port`
/// on the server and relays data bidirectionally.
async fn run_local_forward(
    conversation: Arc<Conversation<ConversationHandle>>,
    spec: ForwardSpec,
) {
    let listener = TcpListener::bind((spec.bind_addr.as_str(), spec.bind_port))
        .await
        .unwrap_or_else(|e| panic!("failed to bind local forward {}:{}: {e}", spec.bind_addr, spec.bind_port));
    tracing::info!(
        bind = %listener.local_addr().unwrap(),
        "local forward listening"
    );

    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "local forward accept failed");
                continue;
            }
        };

        let conv = conversation.clone();
        let dest_host = spec.dest_host.clone();
        let dest_port = spec.dest_port;
        tasks.spawn(
            async move {
                let channel_open = DirectTcpip {
                    dest_host: SshString::from(dest_host),
                    dest_port: VarInt::from(dest_port as u32),
                    originator_host: SshString::from(peer_addr.ip().to_string()),
                    originator_port: VarInt::from(peer_addr.port() as u32),
                };

                let (ch_reader, ch_writer) = match conv
                    .open_channel(&channel_open, DEFAULT_MAX_MESSAGE_SIZE)
                    .await
                {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(
                            error = %snafu::Report::from_error(&e),
                            "direct-tcpip channel open failed"
                        );
                        return;
                    }
                };

                let (tcp_reader, tcp_writer) = tcp_stream.into_split();
                let ch2s = tokio::spawn(relay(ch_reader, tcp_writer).in_current_span());
                let s2ch = tokio::spawn(relay(tcp_reader, ch_writer).in_current_span());
                let _ = tokio::join!(ch2s, s2ch);
            }
            .instrument(tracing::info_span!("forward_conn", %peer_addr)),
        );
    }
}

/// Accept incoming channels from the server and handle `forwarded-tcpip`
/// channels by connecting locally and relaying data.
async fn run_channel_acceptor(
    conversation: Arc<Conversation<ConversationHandle>>,
    remote_targets: Vec<(String, u16, String, u16)>,
) {
    loop {
        let incoming = match conversation.accept_channel().await {
            Ok(ch) => ch,
            Err(e) => {
                tracing::debug!(error = %snafu::Report::from_error(&e), "accept_channel ended");
                break;
            }
        };

        if incoming.channel_type().as_bytes() != b"forwarded-tcpip" {
            tracing::warn!(
                channel_type = %incoming.channel_type(),
                "rejecting unknown incoming channel"
            );
            if let Ok(pending) = incoming
                .decode_payload::<ForwardedTcpip, _>()
                .await
                .map(|(_, p)| p)
            {
                let _ = pending
                    .reject(
                        VarInt::from(1u32),
                        SshString::from_static("unsupported channel type"),
                    )
                    .await;
            }
            continue;
        }

        let (payload, pending): (ForwardedTcpip, _) = match incoming.decode_payload().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %snafu::Report::from_error(&e), "decode forwarded-tcpip failed");
                continue;
            }
        };

        // Find the local target for this forwarded connection.
        let server_port = payload.connected_port.into_inner() as u16;
        let server_addr = payload.connected_address.to_string();
        let target = remote_targets.iter().find(|(bind_addr, port, _, _)| {
            *port == server_port
                && (bind_addr.is_empty()
                    || bind_addr == "0.0.0.0"
                    || bind_addr == "*"
                    || *bind_addr == server_addr)
        });

        let Some((_ba, _bp, local_host, local_port)) = target else {
            tracing::warn!(
                %server_addr, server_port,
                "no matching remote forward target, rejecting"
            );
            let _ = pending
                .reject(
                    VarInt::from(2u32),
                    SshString::from_static("no matching forward"),
                )
                .await;
            continue;
        };

        let local_addr = format!("{local_host}:{local_port}");
        let local_addr_clone = local_addr.clone();
        tokio::spawn(
            async move {
                let tcp_stream = match TcpStream::connect(&local_addr_clone).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            addr = %local_addr_clone,
                            error = %e,
                            "failed to connect to local target"
                        );
                        let _ = pending
                            .reject(
                                VarInt::from(2u32),
                                SshString::from_static("connect failed"),
                            )
                            .await;
                        return;
                    }
                };

                let (ch_reader, ch_writer) = match pending.accept(DEFAULT_MAX_MESSAGE_SIZE).await {
                    Ok(ch) => ch.into_inner(),
                    Err(e) => {
                        tracing::warn!(error = %snafu::Report::from_error(&e), "channel accept failed");
                        return;
                    }
                };

                let (tcp_reader, tcp_writer) = tcp_stream.into_split();
                let ch2s = tokio::spawn(relay(ch_reader, tcp_writer).in_current_span());
                let s2ch = tokio::spawn(relay(tcp_reader, ch_writer).in_current_span());
                let _ = tokio::join!(ch2s, s2ch);
            }
            .instrument(tracing::info_span!("remote_forward_conn", %local_addr, %server_addr, server_port)),
        );
    }
}
