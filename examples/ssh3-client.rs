//! SSH3 client example.
//!
//! Connects to an SSH3 server, opens a session channel, executes a command
//! (or starts an interactive shell), and relays stdin/stdout.
//!
//! Supports OpenSSH-compatible port forwarding:
//! - `-L` — local forwarding (TCP and Unix socket)
//! - `-R` — remote forwarding (TCP and Unix socket)
//! - `-D` — dynamic SOCKS forwarding

use std::io;
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
        DirectStreamlocal, DirectTcpip, ForwardedStreamlocal, ForwardedTcpip, SessionChannelOpen,
        StreamlocalForwardGlobalRequest, StreamlocalForwardRequest, TcpipForwardGlobalRequest,
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

// ============================================================================
// Forwarding specification types
// ============================================================================

/// A network endpoint — either a TCP host:port or a Unix domain socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix { path: String },
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp { host, port } if host.is_empty() => write!(f, "*:{port}"),
            Self::Tcp { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix { path } => f.write_str(path),
        }
    }
}

/// Local forwarding specification (`-L`).
///
/// OpenSSH-compatible syntax:
/// - `[bind_address:]port:host:hostport` — TCP → TCP
/// - `[bind_address:]port:remote_socket` — TCP → Unix socket
/// - `local_socket:host:hostport` — Unix socket → TCP
/// - `local_socket:remote_socket` — Unix socket → Unix socket
#[derive(Debug, Clone)]
struct LocalForward {
    bind: Endpoint,
    connect: Endpoint,
}

impl std::fmt::Display for LocalForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}→{}", self.bind, self.connect)
    }
}

/// Remote forwarding specification (`-R`).
///
/// OpenSSH-compatible syntax:
/// - `[bind_address:]port:host:hostport` — TCP → TCP
/// - `[bind_address:]port:local_socket` — TCP → Unix socket
/// - `remote_socket:host:hostport` — Unix socket → TCP
/// - `remote_socket:local_socket` — Unix socket → Unix socket
/// - `[bind_address:]port` — listen-only (dynamic remote forward)
#[derive(Debug, Clone)]
struct RemoteForward {
    bind: Endpoint,
    connect: Option<Endpoint>,
}

impl std::fmt::Display for RemoteForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.connect {
            Some(c) => write!(f, "{}→{}", self.bind, c),
            None => write!(f, "{} (listen-only)", self.bind),
        }
    }
}

/// Dynamic forwarding specification (`-D`).
///
/// OpenSSH-compatible syntax: `[bind_address:]port`
#[derive(Debug, Clone)]
struct DynamicForward {
    host: String,
    port: u16,
}

impl std::fmt::Display for DynamicForward {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.is_empty() {
            write!(f, "*:{}", self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

// ============================================================================
// PEG parser for OpenSSH-compatible forwarding syntax
// ============================================================================

peg::parser! {
    grammar forward_spec() for str {
        rule unix_path() -> &'input str
            = p:$("/" [^ ':']*) { p }

        rule port() -> u16
            = n:$(['0'..='9']+) {?
                n.parse::<u16>().or(Err("port number 0-65535"))
            }

        rule hostname() -> &'input str
            = h:$([^ ':' | '/' | '[' | ']']+) { h }

        rule bracketed_ipv6() -> &'input str
            = "[" h:$([^ ']']+) "]" { h }

        rule connect_endpoint() -> Endpoint
            = p:unix_path() {
                Endpoint::Unix { path: p.to_owned() }
            }
            / h:bracketed_ipv6() ":" p:port() {
                Endpoint::Tcp { host: h.to_owned(), port: p }
            }
            / h:hostname() ":" p:port() {
                Endpoint::Tcp { host: h.to_owned(), port: p }
            }

        pub rule local_forward() -> LocalForward
            = b:unix_path() ":" c:connect_endpoint() {
                LocalForward { bind: Endpoint::Unix { path: b.to_owned() }, connect: c }
            }
            / h:bracketed_ipv6() ":" bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: h.to_owned(), port: bp },
                    connect: c,
                }
            }
            / "*:" bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: c,
                }
            }
            / bh:hostname() ":" bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: bh.to_owned(), port: bp },
                    connect: c,
                }
            }
            / bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: "127.0.0.1".to_owned(), port: bp },
                    connect: c,
                }
            }

        pub rule remote_forward() -> RemoteForward
            // With connect target
            = b:unix_path() ":" c:connect_endpoint() {
                RemoteForward { bind: Endpoint::Unix { path: b.to_owned() }, connect: Some(c) }
            }
            / h:bracketed_ipv6() ":" bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: h.to_owned(), port: bp },
                    connect: Some(c),
                }
            }
            / "*:" bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: Some(c),
                }
            }
            / bh:hostname() ":" bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: bh.to_owned(), port: bp },
                    connect: Some(c),
                }
            }
            / bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: Some(c),
                }
            }
            // Listen-only (no connect target)
            / h:bracketed_ipv6() ":" bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: h.to_owned(), port: bp },
                    connect: None,
                }
            }
            / "*:" bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: None,
                }
            }
            / bh:hostname() ":" bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: bh.to_owned(), port: bp },
                    connect: None,
                }
            }
            / bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: None,
                }
            }

        pub rule dynamic_forward() -> DynamicForward
            = h:bracketed_ipv6() ":" p:port() {
                DynamicForward { host: h.to_owned(), port: p }
            }
            / "*:" p:port() {
                DynamicForward { host: String::new(), port: p }
            }
            / h:hostname() ":" p:port() {
                DynamicForward { host: h.to_owned(), port: p }
            }
            / p:port() {
                DynamicForward { host: "127.0.0.1".to_owned(), port: p }
            }
    }
}

// ============================================================================
// FromStr for clap integration
// ============================================================================

impl std::str::FromStr for LocalForward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_spec::local_forward(s).map_err(|e| format!("invalid local forward spec '{s}': {e}"))
    }
}

impl std::str::FromStr for RemoteForward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_spec::remote_forward(s)
            .map_err(|e| format!("invalid remote forward spec '{s}': {e}"))
    }
}

impl std::str::FromStr for DynamicForward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_spec::dynamic_forward(s)
            .map_err(|e| format!("invalid dynamic forward spec '{s}': {e}"))
    }
}

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
        forward_tasks.spawn(
            run_local_forward(conv, spec).instrument(tracing::info_span!("local_forward", %label)),
        );
    }

    // Request remote forwards (-R).
    let mut remote_mappings: Vec<RemoteForwardMapping> = Vec::new();
    for spec in &cli.remote_forward {
        match &spec.bind {
            Endpoint::Tcp { host, port } => {
                let request = TcpipForwardGlobalRequest {
                    payload: TcpipForwardRequest {
                        bind_address: SshString::from(host.clone()),
                        bind_port: VarInt::from(*port as u32),
                    },
                };
                let reply = conversation
                    .request(&request)
                    .await
                    .unwrap_or_else(|e| panic!("tcpip-forward request failed: {e}"));
                let allocated_port = reply.allocated_port.into_inner() as u16;
                tracing::info!(
                    bind = %Endpoint::Tcp { host: host.clone(), port: allocated_port },
                    connect = ?spec.connect.as_ref().map(|c| c.to_string()),
                    "remote forward established"
                );
                remote_mappings.push(RemoteForwardMapping {
                    bind: Endpoint::Tcp {
                        host: host.clone(),
                        port: allocated_port,
                    },
                    connect: spec.connect.clone(),
                });
            }
            Endpoint::Unix { path } => {
                let request = StreamlocalForwardGlobalRequest {
                    payload: StreamlocalForwardRequest {
                        socket_path: SshString::from(path.clone()),
                    },
                };
                conversation
                    .request(&request)
                    .await
                    .unwrap_or_else(|e| panic!("streamlocal-forward request failed: {e}"));
                tracing::info!(
                    bind = %spec.bind,
                    connect = ?spec.connect.as_ref().map(|c| c.to_string()),
                    "remote forward established (unix socket)"
                );
                remote_mappings.push(RemoteForwardMapping {
                    bind: Endpoint::Unix { path: path.clone() },
                    connect: spec.connect.clone(),
                });
            }
        }
    }

    // Spawn channel acceptor for remote forwards (-R).
    if !remote_mappings.is_empty() {
        let conv = conversation.clone();
        forward_tasks.spawn(
            run_channel_acceptor(conv, remote_mappings)
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

// ============================================================================
// Local forwarding (-L)
// ============================================================================

/// Run a local forward listener.
///
/// Binds on `spec.bind` (TCP or Unix socket). For each accepted connection,
/// opens a `direct-tcpip` or `direct-streamlocal@openssh.com` channel to
/// `spec.connect` and relays data bidirectionally.
async fn run_local_forward(
    conversation: Arc<Conversation<ConversationHandle>>,
    spec: LocalForward,
) {
    match &spec.bind {
        Endpoint::Tcp { host, port } => {
            let bind_addr = if host.is_empty() {
                "0.0.0.0"
            } else {
                host.as_str()
            };
            let listener = TcpListener::bind((bind_addr, *port))
                .await
                .unwrap_or_else(|e| panic!("failed to bind {}: {e}", spec.bind));
            tracing::info!(bind = %listener.local_addr().unwrap(), "local forward listening");

            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                let conv = conversation.clone();
                let connect = spec.connect.clone();
                let (r, w) = stream.into_split();
                tasks.spawn(
                    forward_local_conn(conv, connect, Box::pin(r), Box::pin(w))
                        .instrument(tracing::info_span!("conn", %peer)),
                );
            }
        }
        Endpoint::Unix { path } => {
            let listener = tokio::net::UnixListener::bind(path)
                .unwrap_or_else(|e| panic!("failed to bind {}: {e}", spec.bind));
            tracing::info!(bind = %spec.bind, "local forward listening");

            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                let conv = conversation.clone();
                let connect = spec.connect.clone();
                let (r, w) = stream.into_split();
                tasks.spawn(
                    forward_local_conn(conv, connect, Box::pin(r), Box::pin(w)).in_current_span(),
                );
            }
        }
    }
}

/// Handle a single local-forward connection: open an SSH channel and relay.
async fn forward_local_conn(
    conversation: Arc<Conversation<ConversationHandle>>,
    connect: Endpoint,
    local_reader: Pin<Box<dyn AsyncRead + Send>>,
    local_writer: Pin<Box<dyn AsyncWrite + Send>>,
) {
    let channel_result = match &connect {
        Endpoint::Tcp { host, port } => {
            conversation
                .open_channel(
                    &DirectTcpip {
                        dest_host: SshString::from(host.clone()),
                        dest_port: VarInt::from(*port as u32),
                        originator_host: SshString::from_static(""),
                        originator_port: VarInt::from(0u32),
                    },
                    DEFAULT_MAX_MESSAGE_SIZE,
                )
                .await
        }
        Endpoint::Unix { path } => {
            conversation
                .open_channel(
                    &DirectStreamlocal {
                        socket_path: SshString::from(path.clone()),
                    },
                    DEFAULT_MAX_MESSAGE_SIZE,
                )
                .await
        }
    };

    let (ch_reader, ch_writer) = match channel_result {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                error = %snafu::Report::from_error(&e),
                dest = %connect,
                "channel open failed"
            );
            return;
        }
    };

    let ch2s = tokio::spawn(relay(ch_reader, local_writer).in_current_span());
    let s2ch = tokio::spawn(relay(local_reader, ch_writer).in_current_span());
    let _ = tokio::join!(ch2s, s2ch);
}

// ============================================================================
// Remote forwarding (-R)
// ============================================================================

/// Mapping from server-side bind endpoint to local connect endpoint.
struct RemoteForwardMapping {
    bind: Endpoint,
    connect: Option<Endpoint>,
}

/// Connect to a local endpoint (TCP or Unix socket).
async fn connect_locally(
    endpoint: &Endpoint,
) -> io::Result<(
    Pin<Box<dyn AsyncRead + Send>>,
    Pin<Box<dyn AsyncWrite + Send>>,
)> {
    match endpoint {
        Endpoint::Tcp { host, port } => {
            let stream = TcpStream::connect((host.as_str(), *port)).await?;
            let (r, w) = stream.into_split();
            Ok((Box::pin(r), Box::pin(w)))
        }
        Endpoint::Unix { path } => {
            let stream = tokio::net::UnixStream::connect(path).await?;
            let (r, w) = stream.into_split();
            Ok((Box::pin(r), Box::pin(w)))
        }
    }
}

/// Accept incoming channels from the server and handle `forwarded-tcpip` and
/// `forwarded-streamlocal@openssh.com` channels by connecting locally and
/// relaying data.
async fn run_channel_acceptor(
    conversation: Arc<Conversation<ConversationHandle>>,
    mappings: Vec<RemoteForwardMapping>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let incoming = match conversation.accept_channel().await {
            Ok(ch) => ch,
            Err(e) => {
                tracing::debug!(error = %snafu::Report::from_error(&e), "accept_channel ended");
                break;
            }
        };

        let channel_type = incoming.channel_type().to_string();

        match channel_type.as_str() {
            "forwarded-tcpip" => {
                let (payload, pending): (ForwardedTcpip, _) = match incoming.decode_payload().await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            error = %snafu::Report::from_error(&e),
                            "decode forwarded-tcpip failed"
                        );
                        continue;
                    }
                };

                let server_port = payload.connected_port.into_inner() as u16;
                let server_addr = payload.connected_address.to_string();

                let mapping = mappings.iter().find(|m| match &m.bind {
                    Endpoint::Tcp { host, port } => {
                        *port == server_port
                            && (host.is_empty()
                                || host == "0.0.0.0"
                                || host == "*"
                                || *host == server_addr)
                    }
                    _ => false,
                });

                let Some(RemoteForwardMapping {
                    connect: Some(connect),
                    ..
                }) = mapping
                else {
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

                let connect = connect.clone();
                tasks.spawn(
                    async move {
                        let (local_reader, local_writer) = match connect_locally(&connect).await {
                            Ok(pair) => pair,
                            Err(e) => {
                                tracing::warn!(
                                    dest = %connect,
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

                        let (ch_reader, ch_writer) =
                            match pending.accept(DEFAULT_MAX_MESSAGE_SIZE).await {
                                Ok(ch) => ch.into_inner(),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %snafu::Report::from_error(&e),
                                        "channel accept failed"
                                    );
                                    return;
                                }
                            };

                        let ch2s = tokio::spawn(relay(ch_reader, local_writer).in_current_span());
                        let s2ch = tokio::spawn(relay(local_reader, ch_writer).in_current_span());
                        let _ = tokio::join!(ch2s, s2ch);
                    }
                    .instrument(tracing::info_span!(
                        "remote_forward_conn",
                        %server_addr,
                        server_port,
                    )),
                );
            }
            "forwarded-streamlocal@openssh.com" => {
                let (payload, pending): (ForwardedStreamlocal, _) =
                    match incoming.decode_payload().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                error = %snafu::Report::from_error(&e),
                                "decode forwarded-streamlocal failed"
                            );
                            continue;
                        }
                    };

                let socket_path = payload.socket_path.to_string();

                let mapping = mappings.iter().find(|m| match &m.bind {
                    Endpoint::Unix { path } => *path == socket_path,
                    _ => false,
                });

                let Some(RemoteForwardMapping {
                    connect: Some(connect),
                    ..
                }) = mapping
                else {
                    tracing::warn!(
                        %socket_path,
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

                let connect = connect.clone();
                tasks.spawn(
                    async move {
                        let (local_reader, local_writer) = match connect_locally(&connect).await {
                            Ok(pair) => pair,
                            Err(e) => {
                                tracing::warn!(
                                    dest = %connect,
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

                        let (ch_reader, ch_writer) =
                            match pending.accept(DEFAULT_MAX_MESSAGE_SIZE).await {
                                Ok(ch) => ch.into_inner(),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %snafu::Report::from_error(&e),
                                        "channel accept failed"
                                    );
                                    return;
                                }
                            };

                        let ch2s = tokio::spawn(relay(ch_reader, local_writer).in_current_span());
                        let s2ch = tokio::spawn(relay(local_reader, ch_writer).in_current_span());
                        let _ = tokio::join!(ch2s, s2ch);
                    }
                    .instrument(tracing::info_span!(
                        "remote_forward_conn",
                        %socket_path,
                    )),
                );
            }
            _ => {
                tracing::warn!(channel_type, "rejecting unknown incoming channel");
                // Best-effort reject — decode as ForwardedTcpip to get PendingChannel.
                if let Ok((_, pending)) = incoming.decode_payload::<ForwardedTcpip, _>().await {
                    let _ = pending
                        .reject(
                            VarInt::from(1u32),
                            SshString::from_static("unsupported channel type"),
                        )
                        .await;
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- LocalForward parsing ---

    #[test]
    fn local_tcp_3part() {
        let f: LocalForward = "8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_4part() {
        let f: LocalForward = "0.0.0.0:8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "0.0.0.0".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_ipv6_bind() {
        let f: LocalForward = "[::1]:8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "::1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_ipv6_connect() {
        let f: LocalForward = "8080:[::1]:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "::1".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_wildcard_bind() {
        let f: LocalForward = "*:8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: String::new(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_to_unix() {
        let f: LocalForward = "8080:/tmp/remote.sock".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Unix {
                path: "/tmp/remote.sock".into()
            }
        );
    }

    #[test]
    fn local_unix_to_tcp() {
        let f: LocalForward = "/tmp/local.sock:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Unix {
                path: "/tmp/local.sock".into()
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_unix_to_unix() {
        let f: LocalForward = "/tmp/local.sock:/tmp/remote.sock".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Unix {
                path: "/tmp/local.sock".into()
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Unix {
                path: "/tmp/remote.sock".into()
            }
        );
    }

    // --- RemoteForward parsing ---

    #[test]
    fn remote_tcp_3part() {
        let f: RemoteForward = "8080:localhost:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: String::new(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Tcp {
                host: "localhost".into(),
                port: 80
            })
        );
    }

    #[test]
    fn remote_tcp_4part() {
        let f: RemoteForward = "0.0.0.0:8080:localhost:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "0.0.0.0".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Tcp {
                host: "localhost".into(),
                port: 80
            })
        );
    }

    #[test]
    fn remote_listen_only_port() {
        let f: RemoteForward = "8080".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: String::new(),
                port: 8080
            }
        );
        assert_eq!(f.connect, None);
    }

    #[test]
    fn remote_listen_only_host_port() {
        let f: RemoteForward = "localhost:8080".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "localhost".into(),
                port: 8080
            }
        );
        assert_eq!(f.connect, None);
    }

    #[test]
    fn remote_unix_to_tcp() {
        let f: RemoteForward = "/tmp/remote.sock:localhost:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Unix {
                path: "/tmp/remote.sock".into()
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Tcp {
                host: "localhost".into(),
                port: 80
            })
        );
    }

    #[test]
    fn remote_tcp_to_unix() {
        let f: RemoteForward = "8080:/tmp/local.sock".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: String::new(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Unix {
                path: "/tmp/local.sock".into()
            })
        );
    }

    // --- DynamicForward parsing ---

    #[test]
    fn dynamic_port_only() {
        let f: DynamicForward = "1080".parse().unwrap();
        assert_eq!(f.host, "127.0.0.1");
        assert_eq!(f.port, 1080);
    }

    #[test]
    fn dynamic_host_port() {
        let f: DynamicForward = "0.0.0.0:1080".parse().unwrap();
        assert_eq!(f.host, "0.0.0.0");
        assert_eq!(f.port, 1080);
    }

    #[test]
    fn dynamic_ipv6() {
        let f: DynamicForward = "[::1]:1080".parse().unwrap();
        assert_eq!(f.host, "::1");
        assert_eq!(f.port, 1080);
    }

    #[test]
    fn dynamic_wildcard() {
        let f: DynamicForward = "*:1080".parse().unwrap();
        assert_eq!(f.host, "");
        assert_eq!(f.port, 1080);
    }

    // --- Display ---

    #[test]
    fn display_endpoint_tcp() {
        assert_eq!(
            Endpoint::Tcp {
                host: "h".into(),
                port: 80
            }
            .to_string(),
            "h:80"
        );
        assert_eq!(
            Endpoint::Tcp {
                host: "::1".into(),
                port: 80
            }
            .to_string(),
            "[::1]:80"
        );
        assert_eq!(
            Endpoint::Tcp {
                host: String::new(),
                port: 80
            }
            .to_string(),
            "*:80"
        );
    }

    #[test]
    fn display_endpoint_unix() {
        assert_eq!(
            Endpoint::Unix {
                path: "/tmp/s".into()
            }
            .to_string(),
            "/tmp/s"
        );
    }
}
