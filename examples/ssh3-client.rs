//! SSH3 client example.
//!
//! Connects to an SSH3 server, opens a session channel, executes a command
//! (or starts an interactive shell), and relays stdin/stdout.

use clap::Parser;
use genmeta_ssh::{
    DEFAULT_MAX_MESSAGE_SIZE, SessionChannelOpen, SshChannel, client::Ssh3Client,
    session::client::ClientSession,
};
use h3x::gm_quic::H3Client;

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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let command: Option<String> = if cli.command.is_empty() {
        None
    } else {
        Some(cli.command.join(" "))
    };

    // Build h3x QUIC client (no server cert verification for demo).
    let client: H3Client = H3Client::builder()
        .without_server_cert_verification()
        .without_identity()
        .expect("failed to configure TLS")
        .build();

    let ssh3_client = Ssh3Client::with_basic_auth(&cli.authority, &cli.user, &cli.password);

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
