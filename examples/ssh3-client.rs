//! SSH3 client example.
//!
//! Connects to an SSH3 server, opens a session channel, executes a command
//! (or starts an interactive shell), and relays stdin/stdout.

use std::pin::Pin;

use clap::Parser;
use genmeta_ssh::{
    client::SSH3_CONNECT_PATH,
    client::encode_basic_auth,
    constants::{DEFAULT_MAX_MESSAGE_SIZE, SSH_VERSION},
    conversation::{Conversation, channel::SshChannel},
    forward::SessionChannelOpen,
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
    let session_id = StreamId::try_from(conversation_id).unwrap();
    let handle = protocol
        .register(session_id)
        .whatever_context("failed to register conversation")?;

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
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let command: Option<String> = if cli.command.is_empty() {
        None
    } else {
        Some(cli.command.join(" "))
    };

    let client: H3Client = H3Client::builder()
        .without_server_cert_verification()
        .without_identity()
        .expect("failed to configure TLS")
        .build();

    let auth_header = encode_basic_auth(&cli.user, &cli.password);
    let conversation = connect(&cli.authority, auth_header, &client)
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
    use genmeta_ssh::session::client::SessionEvent;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = [0u8; 4096];
    let mut stdin_eof = false;
    let mut exit_code: Option<u32> = None;

    loop {
        tokio::select! {
            result = stdin.read(&mut stdin_buf), if !stdin_eof => {
                match result {
                    Ok(0) | Err(_) => {
                        stdin_eof = true;
                        let _ = session.send_eof().await;
                    }
                    Ok(n) => {
                        if session.send_stdin(&stdin_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            result = session.recv_event() => {
                match result {
                    Ok(Some(SessionEvent::Stdout(data))) => {
                        stdout.write_all(data.as_ref()).await.expect("stdout write");
                    }
                    Ok(Some(SessionEvent::Stderr(data))) => {
                        stderr.write_all(data.as_ref()).await.expect("stderr write");
                    }
                    Ok(Some(SessionEvent::ExitStatus(code))) => {
                        exit_code = Some(code);
                    }
                    Ok(Some(SessionEvent::Close)) | Ok(None) => break,
                    Ok(Some(_)) => {}
                    Err(e) => {
                        tracing::error!(error = %snafu::Report::from_error(&e), "session error");
                        break;
                    }
                }
            }
        }
    }

    std::process::exit(exit_code.unwrap_or(1) as i32);
}
