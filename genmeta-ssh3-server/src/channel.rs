//! SSH3 channel lifecycle and message loop.
//!
//! Each QUIC bidirectional stream dispatched by [`Ssh3Protocol`] carries a
//! [`ChannelHeader`] identifying the channel type. This module handles:
//!
//! - Dispatching by `channel_type` (session, forwarding stubs, unknown)
//! - Sending `ChannelOpenConfirmation(91)` or `ChannelOpenFailure(92)`
//! - Running the session channel message loop (data, requests, EOF, close)

use std::os::fd::AsRawFd;
use std::sync::Arc;

use genmeta_ssh3_proto::{codec::ChannelHeader, message::SshMessage};
use genmeta_ssh3_proto::session::{SessionInit, SshSession, SshSessionClient};
use h3x::codec::{DecodeFrom, EncodeInto};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::forward;
use crate::forward::reverse_tcp::ReverseTcpForwarder;
use crate::forward::streamlocal::ReverseStreamlocalForwarder;
use crate::session::pty::{PtyPair, allocate_pty, set_window_size};
use crate::session::request::{handle_request, RequestAction, run_exec, run_shell};

// ---------------------------------------------------------------------------
// Global request context for reverse forwarding
// ---------------------------------------------------------------------------

/// Context passed to `handle_channel` for handling `"global-request"` channels.
///
/// Contains the reverse TCP and streamlocal forwarders, the stream factory for
/// opening server-initiated QUIC streams, and the conversation ID.
pub struct GlobalRequestContext {
    /// Reverse TCP forwarder (manages `tcpip-forward` listeners).
    pub tcp_forwarder: Arc<ReverseTcpForwarder>,
    /// Reverse streamlocal forwarder (manages `streamlocal-forward@openssh.com` listeners).
    pub streamlocal_forwarder: Arc<ReverseStreamlocalForwarder>,
    /// Factory for opening server-initiated QUIC bidirectional streams.
    pub stream_factory: forward::StreamFactory,
    /// Conversation ID for opened channels.
    pub conversation_id: u64,
}
// ---------------------------------------------------------------------------
// Channel events dispatched via mpsc
// ---------------------------------------------------------------------------

/// Events produced by the channel message loop and sent to the session layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEvent {
    /// ChannelData(94) — standard channel data.
    Data(Vec<u8>),
    /// ChannelExtendedData(95) — extended data (e.g., stderr when data_type=1).
    ExtendedData { data_type: u64, data: Vec<u8> },
    /// ChannelRequest(98) — channel request with type and opaque payload.
    Request {
        request_type: String,
        want_reply: bool,
        request_data: Vec<u8>,
    },
    /// ChannelEof(96) — remote side signals end of input.
    Eof,
    /// ChannelClose(97) — remote side closes the channel.
    Close,
}

/// Default maximum message size for session channels.
pub const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Channel dispatch by type
// ---------------------------------------------------------------------------

/// Handle a dispatched channel stream.
///
/// Reads the `channel_type` from the [`ChannelHeader`] and dispatches:
/// - `"session"` → confirm + run message loop
/// - `"global-request"` → decode and handle global requests (requires `global_ctx`)
/// - TCP/streamlocal forwarding types → appropriate handler
/// - Unknown → send `ChannelOpenFailure(92)` with reason_code=3
pub async fn handle_channel<R, W>(
    header: ChannelHeader,
    reader: R,
    writer: W,
    global_ctx: Option<Arc<GlobalRequestContext>>,
    session_client: Option<SshSessionClient>,
    session_init: Option<SessionInit>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    match header.channel_type.as_str() {
        "session" => {
            let session_client = session_client.ok_or_else(|| {
                io::Error::other("no session client available")
            })?;
            let session_init = session_init.ok_or_else(|| {
                io::Error::other("no session init available")
            })?;
            handle_session_byte_bridge(header, reader, writer, session_client, session_init).await
        }
        "direct-tcpip" => forward::direct_tcp::handle_direct_tcp(header, reader, writer).await,
        "direct-streamlocal@openssh.com" => forward::streamlocal::handle_direct_streamlocal(header, reader, writer).await,
        "socks5" => forward::socks5::handle_socks5(header, reader, writer).await,
        "forwarded-tcpip" | "forwarded-streamlocal@openssh.com" => {
            // Stub dispatch points — server-initiated channels, not normally received here.
            Ok(())
        }
        "global-request" => {
            handle_global_request_channel(reader, writer, global_ctx).await
        }
        _ => {
            handle_unknown_channel(header, writer).await
        }
    }
}

/// Handle an unknown channel type by sending `ChannelOpenFailure(92)`.
async fn handle_unknown_channel<W>(
    _header: ChannelHeader,
    mut writer: W,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let failure = SshMessage::ChannelOpenFailure {
        reason_code: 3,
        description: "unknown channel type".into(),
    };
    failure.encode_into(&mut writer).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Global request channel handling
// ---------------------------------------------------------------------------

/// Handle a `"global-request"` channel.
///
/// This channel type carries SSH `GlobalRequest(80)` messages. Unlike session
/// channels, no `ChannelOpenConfirmation` is sent. The server decodes the
/// `GlobalRequest`, dispatches by `request_type`, and sends back
/// `RequestSuccess(81)` or `RequestFailure(82)`.
async fn handle_global_request_channel<R, W>(
    mut reader: R,
    mut writer: W,
    global_ctx: Option<Arc<GlobalRequestContext>>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    use crate::forward::reverse_tcp::{TcpipForwardRequest, CancelTcpipForwardRequest, TcpipForwardReply};
    use crate::forward::streamlocal::{StreamlocalForwardRequest, CancelStreamlocalForwardRequest};

    // Read a single GlobalRequest from the stream.
    let msg = SshMessage::decode_from(&mut reader).await?;

    let SshMessage::GlobalRequest {
        request_type,
        want_reply,
        data,
    } = msg
    else {
        tracing::warn!("expected GlobalRequest on global-request channel, got {msg:?}");
        return Ok(());
    };

    let ctx = match global_ctx {
        Some(ctx) => ctx,
        None => {
            tracing::warn!("global-request channel received but no GlobalRequestContext");
            if want_reply {
                SshMessage::RequestFailure.encode_into(&mut writer).await?;
            }
            return Ok(());
        }
    };

    match request_type.as_str() {
        "tcpip-forward" => {
            let req = TcpipForwardRequest::decode_from_bytes(&data).await?;
            tracing::info!(
                bind_address = %req.bind_address,
                bind_port = req.bind_port,
                "tcpip-forward request"
            );
            match ctx.tcp_forwarder.start_listening(
                &req.bind_address,
                req.bind_port as u16,
                ctx.stream_factory.clone(),
                ctx.conversation_id,
            ).await {
                Ok(actual_port) => {
                    if want_reply {
                        let reply_data = TcpipForwardReply {
                            allocated_port: actual_port as u32,
                        }
                        .encode_to_bytes()
                        .await;
                        SshMessage::RequestSuccess { data: reply_data }
                            .encode_into(&mut writer)
                            .await?;
                    }
                }
                Err(e) => {
                    tracing::warn!(%e, "tcpip-forward bind failed");
                    if want_reply {
                        SshMessage::RequestFailure.encode_into(&mut writer).await?;
                    }
                }
            }
        }
        "cancel-tcpip-forward" => {
            let req = CancelTcpipForwardRequest::decode_from_bytes(&data).await?;
            tracing::info!(
                bind_address = %req.bind_address,
                bind_port = req.bind_port,
                "cancel-tcpip-forward request"
            );
            let stopped = ctx.tcp_forwarder.stop_listening(
                &req.bind_address,
                req.bind_port as u16,
            ).await;
            if want_reply {
                if stopped {
                    SshMessage::RequestSuccess { data: vec![] }
                        .encode_into(&mut writer)
                        .await?;
                } else {
                    SshMessage::RequestFailure.encode_into(&mut writer).await?;
                }
            }
        }
        "streamlocal-forward@openssh.com" => {
            let req = StreamlocalForwardRequest::decode_from_bytes(&data).await?;
            tracing::info!(
                socket_path = %req.socket_path,
                "streamlocal-forward request"
            );
            match ctx.streamlocal_forwarder.start_listening(
                &req.socket_path,
                ctx.stream_factory.clone(),
                ctx.conversation_id,
            ).await {
                Ok(()) => {
                    if want_reply {
                        SshMessage::RequestSuccess { data: vec![] }
                            .encode_into(&mut writer)
                            .await?;
                    }
                }
                Err(e) => {
                    tracing::warn!(%e, "streamlocal-forward bind failed");
                    if want_reply {
                        SshMessage::RequestFailure.encode_into(&mut writer).await?;
                    }
                }
            }
        }
        "cancel-streamlocal-forward@openssh.com" => {
            let req = CancelStreamlocalForwardRequest::decode_from_bytes(&data).await?;
            tracing::info!(
                socket_path = %req.socket_path,
                "cancel-streamlocal-forward request"
            );
            let stopped = ctx.streamlocal_forwarder.stop_listening(
                &req.socket_path,
            ).await;
            if want_reply {
                if stopped {
                    SshMessage::RequestSuccess { data: vec![] }
                        .encode_into(&mut writer)
                        .await?;
                } else {
                    SshMessage::RequestFailure.encode_into(&mut writer).await?;
                }
            }
        }
        _ => {
            tracing::warn!(request_type, "unknown global request type");
            if want_reply {
                SshMessage::RequestFailure.encode_into(&mut writer).await?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Session channel lifecycle
// ---------------------------------------------------------------------------

/// Handle a session channel: confirm opening, then run the message loop.
///
/// Returns `(event_rx, io::Result<()>)` via spawning, but for direct use
/// this function drives the loop to completion.
pub async fn handle_session_channel<R, W>(
    _header: ChannelHeader,
    reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    confirm.encode_into(&mut writer).await?;

    // Spawn the message-loop reader, producing events into the channel.
    let (event_tx, mut event_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        let _ = run_message_loop_with_sender(reader, event_tx).await;
    });

    // Dispatch loop: consume events until an exec/shell request arrives.
    // Tracks PTY allocation state: None (idle) or Some(PtyPair) (PTY allocated).
    let mut pty_pair: Option<PtyPair> = None;

    while let Some(event) = event_rx.recv().await {
        match event {
            ChannelEvent::Request { .. } => {
                match handle_request(&event, &mut writer).await? {
                    Some(RequestAction::Exec(cmd)) => {
                        run_exec(&cmd, &mut writer, event_rx, pty_pair.take()).await?;
                        return Ok(());
                    }
                    Some(RequestAction::Shell) => {
                        let shell = std::env::var("SHELL")
                            .unwrap_or_else(|_| "/bin/sh".to_string());
                        run_shell(&shell, &mut writer, event_rx, pty_pair.take()).await?;
                        return Ok(());
                    }
                    Some(RequestAction::AllocatePty(req)) => {
                        match allocate_pty(&req) {
                            Ok(pair) => {
                                pty_pair = Some(pair);
                                tracing::info!(term = %req.term_type, "PTY allocated");
                            }
                            Err(e) => {
                                tracing::error!(%e, "PTY allocation failed");
                                // PTY failure is non-fatal — exec/shell will use piped stdio
                            }
                        }
                    }
                    Some(RequestAction::WindowChange(req)) => {
                        if let Some(ref pair) = pty_pair {
                            let _ = set_window_size(pair.master.as_raw_fd(), &req);
                        }
                    }
                    Some(RequestAction::Signal(_)) => {
                        // Signal before exec/shell — no process to signal yet
                        tracing::debug!("ignoring signal before exec/shell");
                    }
                    None => { /* unrecognized request, continue loop */ }
                }
            }
            ChannelEvent::Eof => {
                SshMessage::ChannelEof.encode_into(&mut writer).await?;
                writer.shutdown().await?;
                break;
            }
            ChannelEvent::Close => {
                SshMessage::ChannelClose.encode_into(&mut writer).await?;
                break;
            }
            ChannelEvent::Data(_) | ChannelEvent::ExtendedData { .. } => {
                // No exec/shell running yet — data before a request is meaningless.
            }
        }
    }

    Ok(())
}

/// Handle a session channel by bridging raw bytes to the child process.
///
/// Creates two remoc byte channel pairs and spawns bridge tasks:
/// - QUIC reader → from_client_tx (raw bytes to child)
/// - to_client_rx → QUIC writer (raw bytes from child)
///
/// The child process sends ChannelOpenConfirmation and handles all SSH
/// message parsing/dispatch — the parent is a pure byte relay.
async fn handle_session_byte_bridge<R, W>(
    _header: ChannelHeader,
    mut reader: R,
    mut writer: W,
    session_client: SshSessionClient,
    init: SessionInit,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // 1. Create remoc byte channels (parent-side endpoints)
    let (from_client_tx, from_client_rx) = remoc::rch::mpsc::channel(64);
    let (to_client_tx, to_client_rx) = remoc::rch::mpsc::channel(64);

    // 2. Spawn the RTC call to the child (non-blocking)
    let session_handle = tokio::spawn(async move {
        session_client.run_session(init, from_client_rx, to_client_tx).await
    });

    // 3. Spawn byte bridge: QUIC reader → from_client_tx (raw bytes to child)
    let bridge_to_child = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 { break; }
            if from_client_tx.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
        Ok::<(), io::Error>(())
    });

    // 4. Spawn byte bridge: to_client_rx → QUIC writer (raw bytes from child)
    let bridge_from_child = tokio::spawn(async move {
        let mut to_client_rx = to_client_rx;
        loop {
            match to_client_rx.recv().await {
                Ok(Some(data)) => {
                    writer.write_all(&data).await?;
                    writer.flush().await?;
                }
                Ok(None) => break, // channel closed
                Err(_) => break,   // channel error
            }
        }
        writer.shutdown().await?;
        Ok::<(), io::Error>(())
    });

    // 5. Wait for all tasks
    let _ = tokio::try_join!(
        async { bridge_to_child.await.map_err(io::Error::other)? },
        async { bridge_from_child.await.map_err(io::Error::other)? },
        async {
            session_handle.await
                .map_err(io::Error::other)?
                .map_err(|e| io::Error::other(e.to_string()))
        },
    );

    Ok(())
}

/// Open a session channel, send confirmation, and return the event receiver
/// along with a writer for sending messages back.
///
/// This is the public API for the session layer to consume channel events.
pub async fn open_session_channel<R, W>(
    reader: R,
    mut writer: W,
) -> io::Result<(mpsc::Receiver<ChannelEvent>, W)>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    confirm.encode_into(&mut writer).await?;

    let (event_tx, event_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        let _ = run_message_loop_with_sender(reader, event_tx).await;
    });
    Ok((event_rx, writer))
}

// ---------------------------------------------------------------------------
// Message loop
// ---------------------------------------------------------------------------

/// Run the channel message loop, returning an event receiver and the loop result.
#[allow(dead_code)]
async fn run_message_loop<R, W>(
    reader: R,
    _writer: W,
) -> (mpsc::Receiver<ChannelEvent>, io::Result<()>)
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let (event_tx, event_rx) = mpsc::channel(64);
    let result = run_message_loop_with_sender(reader, event_tx).await;
    (event_rx, result)
}

/// Core message loop: reads `SshMessage` from the stream, dispatches to mpsc.
pub async fn run_message_loop_with_sender<R>(
    mut reader: R,
    event_tx: mpsc::Sender<ChannelEvent>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin,
{
    loop {
        let msg = match SshMessage::decode_from(&mut reader).await {
            Ok(msg) => msg,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Stream closed — normal termination.
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match msg {
            SshMessage::ChannelData { data } => {
                let _ = event_tx.send(ChannelEvent::Data(data)).await;
            }
            SshMessage::ChannelExtendedData { data_type, data } => {
                let _ = event_tx
                    .send(ChannelEvent::ExtendedData { data_type, data })
                    .await;
            }
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                let _ = event_tx
                    .send(ChannelEvent::Request {
                        request_type,
                        want_reply,
                        request_data,
                    })
                    .await;
            }
            SshMessage::ChannelEof => {
                let _ = event_tx.send(ChannelEvent::Eof).await;
            }
            SshMessage::ChannelClose => {
                let _ = event_tx.send(ChannelEvent::Close).await;
                return Ok(());
            }
            SshMessage::ChannelSuccess => {
                tracing::debug!("received ChannelSuccess(99)");
            }
            SshMessage::ChannelFailure => {
                tracing::debug!("received ChannelFailure(100)");
            }
            other => {
                tracing::warn!("unexpected message in channel loop: {other:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::{codec::ChannelHeader, message::SshMessage};
    use tokio::io::duplex;

    /// Helper: encode messages into writer half, then drop to signal EOF.
    async fn encode_messages(mut writer: impl AsyncWrite + Send + Unpin, messages: &[SshMessage]) {
        for msg in messages {
            msg.encode_into(&mut writer).await.unwrap();
        }
        drop(writer);
    }

    // -----------------------------------------------------------------------
    // Test 1: session channel lifecycle — open → confirm → data → EOF → close
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_lifecycle() {
        let (client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 65536,
        };

        // Client sends: data → EOF → close
        let client_handle = tokio::spawn(async move {
            let messages = vec![
                SshMessage::ChannelData {
                    data: b"hello".to_vec(),
                },
                SshMessage::ChannelEof,
                SshMessage::ChannelClose,
            ];
            encode_messages(client_writer, &messages).await;
        });

        // Server handles the channel (directly, bypassing byte bridge dispatch)
        let server_handle = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .unwrap();
        });

        // Read the ChannelOpenConfirmation from the server
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match confirm {
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
                assert_eq!(max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
            }
            other => panic!("expected ChannelOpenConfirmation, got {other:?}"),
        }

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 2: unknown channel type → ChannelOpenFailure(92) with reason_code=3
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_channel_type_sends_failure() {
        let (_client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "unknown-type".into(),
            max_message_size: 65536,
        };

        handle_channel(header, server_reader, server_writer, None, None, None)
            .await
            .unwrap();

        // Read the ChannelOpenFailure from the server
        let failure = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match failure {
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(reason_code, 3, "reason_code should be 3 (unknown channel type)");
                assert_eq!(description, "unknown channel type");
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: session channel receives ChannelData → event dispatched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_data_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Send data then close
        let client_handle = tokio::spawn(async move {
            SshMessage::ChannelData {
                data: b"test-data".to_vec(),
            }.encode_into(&mut client_writer)
            .await
            .unwrap();
            SshMessage::ChannelClose.encode_into(&mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        // Use open_session_channel to get the event receiver
        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation from client side
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // Receive the data event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Data(b"test-data".to_vec()));

        // Receive close event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 4: session channel receives ChannelRequest → event dispatched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_request_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::ChannelRequest {
                request_type: "exec".into(),
                want_reply: true,
                request_data: b"ls -la".to_vec(),
            }.encode_into(&mut client_writer)
            .await
            .unwrap();
            SshMessage::ChannelClose.encode_into(&mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();

        // Receive the request event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChannelEvent::Request {
                request_type: "exec".into(),
                want_reply: true,
                request_data: b"ls -la".to_vec(),
            }
        );

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 5: session channel receives ChannelEof → EOF event
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_eof_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::ChannelEof.encode_into(&mut client_writer)
                .await
                .unwrap();
            SshMessage::ChannelClose.encode_into(&mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();

        // Receive EOF event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Eof);

        // Receive close event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 6: session channel receives ChannelClose → close event
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_close_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::ChannelClose.encode_into(&mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();

        // Receive close event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        // Channel should be done — no more events
        assert!(event_rx.recv().await.is_none());

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 7: forwarding channel types are stub-accepted (return Ok)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn forwarding_channel_types_stub() {
        let forwarding_types = [
            "forwarded-tcpip",
            "forwarded-streamlocal@openssh.com",
        ];

        for channel_type in forwarding_types {
            let (_, server_reader) = duplex(8192);
            let (server_writer, _) = duplex(8192);

            let header = ChannelHeader {
                signal_value: 0xaf3627e6,
                conversation_id: 1,
                channel_type: channel_type.into(),
                max_message_size: 65536,
            };

            let result = handle_channel(header, server_reader, server_writer, None, None, None).await;
            assert!(
                result.is_ok(),
                "forwarding type {channel_type} should return Ok(())"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: ChannelExtendedData dispatched as ExtendedData event
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_extended_data_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::ChannelExtendedData {
                data_type: 1, // stderr
                data: b"error output".to_vec(),
            }.encode_into(&mut client_writer)
            .await
            .unwrap();
            SshMessage::ChannelClose.encode_into(&mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();

        // Receive extended data event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChannelEvent::ExtendedData {
                data_type: 1,
                data: b"error output".to_vec(),
            }
        );

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 9: ChannelSuccess/ChannelFailure are logged, not dispatched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_success_failure_logged() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            // Send success and failure, then close
            SshMessage::ChannelSuccess.encode_into(&mut client_writer)
                .await
                .unwrap();
            SshMessage::ChannelFailure.encode_into(&mut client_writer)
                .await
                .unwrap();
            SshMessage::ChannelData {
                data: b"after".to_vec(),
            }.encode_into(&mut client_writer)
            .await
            .unwrap();
            SshMessage::ChannelClose.encode_into(&mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();

        // ChannelSuccess and ChannelFailure should NOT appear as events.
        // The next event should be the data message.
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Data(b"after".to_vec()));

        // Then close
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        client_handle.await.unwrap();
    }
}
