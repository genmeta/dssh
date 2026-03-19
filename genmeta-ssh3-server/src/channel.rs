//! SSH3 channel lifecycle and message loop.
//!
//! Each QUIC bidirectional stream dispatched by [`Ssh3Protocol`] carries a
//! [`ChannelHeader`] identifying the channel type. This module handles:
//!
//! - Dispatching by `channel_type` (session, forwarding stubs, unknown)
//! - Sending `ChannelOpenConfirmation(91)` or `ChannelOpenFailure(92)`
//! - Running the session channel message loop (data, requests, EOF, close)

use std::{future::Future, pin::Pin, sync::Arc};

use genmeta_ssh::{
    codec::ChannelHeader,
    message::SshMessage,
};
use genmeta_ssh::{
    CancelStreamlocalForwardRequest, CancelTcpipForwardRequest, StreamlocalForwardRequest,
    TcpipForwardReply, TcpipForwardRequest,
};
use genmeta_ssh::{Ssh3Transport as RemoteSsh3Transport, Ssh3TransportClient, TransportError};
use h3x::codec::{DecodeExt, EncodeExt};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use snafu::Report;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tracing::Instrument;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc as StdArc};

use crate::forward::reverse_tcp::ReverseTcpForwarder;
use crate::forward::streamlocal::ReverseStreamlocalForwarder;
pub use crate::session::handle_session_channel;
use crate::protocol::DispatchedStream;

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
    /// Parent transport client used to open server-initiated channels.
    pub transport: Ssh3TransportClient,
    /// Conversation ID for opened channels.
    pub conversation_id: StreamId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRequestReply {
    Success(Vec<u8>),
    Failure,
}

enum ControlStreamAction {
    Reply { want_reply: bool, reply: GlobalRequestReply },
    Close,
}

fn validate_global_request_port(bind_port: u32) -> io::Result<u16> {
    u16::try_from(bind_port).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("bind port {bind_port} is out of range for a TCP port"),
        )
    })
}
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
    _reader: R,
    writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    handle_unknown_channel(header, writer).await
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
        reason_code: VarInt::from(3u8),
        description: "unknown channel type".into(),
    };
    writer.encode_one(&failure).await?;
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
pub async fn handle_global_request_channel<R, W>(
    mut reader: R,
    mut writer: W,
    global_ctx: Option<Arc<GlobalRequestContext>>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Read a single GlobalRequest from the stream.
    let msg: SshMessage = reader.decode_one().await?;

    let SshMessage::GlobalRequest {
        request_type,
        want_reply,
        data,
    } = msg
    else {
        tracing::warn!("expected GlobalRequest on global-request channel, got {msg:?}");
        return Ok(());
    };

    let reply = process_global_request(&request_type, &data, global_ctx).await?;
    if want_reply {
        match reply {
            GlobalRequestReply::Success(data) => {
                writer.encode_one(&SshMessage::RequestSuccess { data }).await?
            }
            GlobalRequestReply::Failure => {
                writer.encode_one(&SshMessage::RequestFailure).await?
            }
        }
        writer.flush().await?;
    }

    Ok(())
}

pub async fn process_global_request(
    request_type: &str,
    mut data: &[u8],
    global_ctx: Option<Arc<GlobalRequestContext>>,
) -> io::Result<GlobalRequestReply> {
    let ctx = match global_ctx {
        Some(ctx) => ctx,
        None => {
            tracing::warn!("global request received but no GlobalRequestContext");
            return Ok(GlobalRequestReply::Failure);
        }
    };

    match request_type {
        "tcpip-forward" => {
            let req: TcpipForwardRequest = data.decode_one().await?;
            tracing::info!(bind_address = %req.bind_address, bind_port = req.bind_port, "tcpip-forward request");
            let bind_port = match validate_global_request_port(req.bind_port) {
                Ok(port) => port,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(&error), bind_port = req.bind_port, "tcpip-forward bind rejected");
                    return Ok(GlobalRequestReply::Failure);
                }
            };

            match ctx
                .tcp_forwarder
                .start_listening(&req.bind_address, bind_port, ctx.transport.clone(), ctx.conversation_id)
                .await
            {
                Ok(actual_port) => {
                    let mut reply_data = Vec::new();
                    reply_data
                        .encode_one(&TcpipForwardReply {
                        allocated_port: actual_port as u32,
                        })
                        .await?;
                    Ok(GlobalRequestReply::Success(reply_data))
                }
                Err(e) => {
                    tracing::warn!(%e, "tcpip-forward bind failed");
                    Ok(GlobalRequestReply::Failure)
                }
            }
        }
        "cancel-tcpip-forward" => {
            let req: CancelTcpipForwardRequest = data.decode_one().await?;
            tracing::info!(bind_address = %req.bind_address, bind_port = req.bind_port, "cancel-tcpip-forward request");
            let bind_port = match validate_global_request_port(req.bind_port) {
                Ok(port) => port,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(&error), bind_port = req.bind_port, "cancel-tcpip-forward rejected");
                    return Ok(GlobalRequestReply::Failure);
                }
            };

            let stopped = ctx
                .tcp_forwarder
                .stop_listening(&req.bind_address, bind_port, ctx.conversation_id)
                .await;
            if stopped {
                Ok(GlobalRequestReply::Success(vec![]))
            } else {
                Ok(GlobalRequestReply::Failure)
            }
        }
        "streamlocal-forward@openssh.com" => {
            let req: StreamlocalForwardRequest = data.decode_one().await?;
            tracing::info!(socket_path = %req.socket_path, "streamlocal-forward request");
            match ctx
                .streamlocal_forwarder
                .start_listening(&req.socket_path, ctx.transport.clone(), ctx.conversation_id)
                .await
            {
                Ok(()) => Ok(GlobalRequestReply::Success(vec![])),
                Err(e) => {
                    tracing::warn!(%e, "streamlocal-forward bind failed");
                    Ok(GlobalRequestReply::Failure)
                }
            }
        }
        "cancel-streamlocal-forward@openssh.com" => {
            let req: CancelStreamlocalForwardRequest = data.decode_one().await?;
            tracing::info!(socket_path = %req.socket_path, "cancel-streamlocal-forward request");
            let stopped = ctx
                .streamlocal_forwarder
                .stop_listening(&req.socket_path, ctx.conversation_id)
                .await;
            if stopped {
                Ok(GlobalRequestReply::Success(vec![]))
            } else {
                Ok(GlobalRequestReply::Failure)
            }
        }
        _ => {
            tracing::warn!(request_type, "unknown global request type");
            Ok(GlobalRequestReply::Failure)
        }
    }
}

pub async fn reject_legacy_global_request_channel<W>(mut writer: W) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let failure = SshMessage::ChannelOpenFailure {
        reason_code: VarInt::from(3u8),
        description: "legacy global-request channel path rejected; use control stream".into(),
    };
    writer.encode_one(&failure).await?;
    writer.flush().await
}

pub async fn serve_control_stream_global_requests<R, W>(
    mut reader: R,
    writer: W,
    readiness: StdArc<AtomicBool>,
    global_ctx: Option<Arc<GlobalRequestContext>>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    serve_control_stream_global_requests_with_handler(
        &mut reader,
        writer,
        readiness,
        global_ctx,
        |request_type, data, global_ctx| async move {
            process_global_request(&request_type, &data, global_ctx).await
        },
    )
    .await
}

pub async fn serve_control_stream_global_requests_with_handler<R, W, H, Fut>(
    reader: &mut R,
    writer: W,
    readiness: StdArc<AtomicBool>,
    global_ctx: Option<Arc<GlobalRequestContext>>,
    handler: H,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    H: Fn(String, Vec<u8>, Option<Arc<GlobalRequestContext>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<GlobalRequestReply>> + Send + 'static,
{
    let handler = StdArc::new(handler);
    let (action_tx, mut action_rx) = mpsc::channel::<ControlStreamAction>(16);
    let in_flight = StdArc::new(AtomicBool::new(false));

    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(action) = action_rx.recv().await {
            match action {
                ControlStreamAction::Reply { want_reply, reply } => {
                    if want_reply {
                        match reply {
                            GlobalRequestReply::Success(data) => {
                                writer.encode_one(&SshMessage::RequestSuccess { data }).await?
                            }
                            GlobalRequestReply::Failure => {
                                writer.encode_one(&SshMessage::RequestFailure).await?
                            }
                        }
                        writer.flush().await?;
                    }
                }
                ControlStreamAction::Close => {
                    writer.shutdown().await?;
                    break;
                }
            }
        }
        Ok::<(), io::Error>(())
    });

    loop {
        let msg = match reader.decode_one::<SshMessage>().await {
            Ok(msg) => msg,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                drop(action_tx);
                let _ = writer_task.await;
                return Err(error);
            }
        };

        let SshMessage::GlobalRequest {
            request_type,
            want_reply,
            data,
        } = msg
        else {
            let _ = action_tx.send(ControlStreamAction::Close).await;
            break;
        };

        if !readiness.load(Ordering::SeqCst) {
            let _ = action_tx
                .send(ControlStreamAction::Reply {
                    want_reply,
                    reply: GlobalRequestReply::Failure,
                })
                .await;
            continue;
        }

        if in_flight.swap(true, Ordering::SeqCst) {
            let _ = action_tx
                .send(ControlStreamAction::Reply {
                    want_reply,
                    reply: GlobalRequestReply::Failure,
                })
                .await;
            continue;
        }

        let handler = StdArc::clone(&handler);
        let action_tx = action_tx.clone();
        let in_flight = StdArc::clone(&in_flight);
        let global_ctx = global_ctx.clone();
        tokio::spawn(async move {
            let reply = match handler(request_type, data, global_ctx).await {
                Ok(reply) => reply,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(&error), "global request handling failed");
                    GlobalRequestReply::Failure
                }
            };

            let _ = action_tx
                .send(ControlStreamAction::Reply { want_reply, reply })
                .await;
            in_flight.store(false, Ordering::SeqCst);
        });
    }

    drop(action_tx);
    match writer_task.await {
        Ok(result) => result,
        Err(error) => Err(io::Error::other(error)),
    }
}

// ---------------------------------------------------------------------------
// Session channel lifecycle
// ---------------------------------------------------------------------------

/// Handle a session channel: confirm opening, then run the message loop.
///
/// Returns `(event_rx, io::Result<()>)` via spawning, but for direct use
/// this function drives the loop to completion.
/// Handle an open-channel request from the child process.
///
/// Opens a new channel via transport and returns remoc
/// channel endpoints to the child.
pub async fn handle_open_channel_request(
    header: Option<ChannelHeader>,
    transport: &Ssh3TransportClient,
) -> Result<
    (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
    genmeta_ssh::SessionError,
> {
    use genmeta_ssh::SessionError;

    let (from_remote_rx, to_remote_tx) = transport
        .open_channel(header)
        .await
        .map_err(|_| SessionError::new("failed to open channel"))?;
    Ok((from_remote_rx, to_remote_tx))
}

pub struct ConversationEndpoint {
    conversation_id: StreamId,
    channel_rx: mpsc::Receiver<DispatchedStream>,
    opener: OpenBiFactory,
}

impl ConversationEndpoint {
    pub(crate) fn new(
        conversation_id: StreamId,
        channel_rx: mpsc::Receiver<DispatchedStream>,
        opener: OpenBiFactory,
    ) -> Self {
        Self {
            conversation_id,
            channel_rx,
            opener,
        }
    }

    /// Returns the conversation ID (u64 from the QUIC stream ID).
    pub fn conversation_id(&self) -> StreamId {
        self.conversation_id
    }

    /// Accept the next dispatched channel stream from the remote peer.
    ///
    /// Returns `None` when the conversation is closed (sender dropped).
    pub async fn accept_channel(&mut self) -> Option<DispatchedStream> {
        self.channel_rx.recv().await
    }

    pub async fn open_stream(
        &self,
    ) -> io::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        (self.opener)().await
    }

}

pub type OpenBiFactory = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )>> + Send>>
    + Send + Sync,
>;

pub struct Ssh3Transport {
    endpoint: tokio::sync::Mutex<ConversationEndpoint>,
}

impl Ssh3Transport {
    /// Create a transport with a known endpoint.
    pub fn new(endpoint: ConversationEndpoint) -> Self {
        Self {
            endpoint: tokio::sync::Mutex::new(endpoint),
        }
    }
}

impl RemoteSsh3Transport for Ssh3Transport {
    async fn accept_channel(&self) -> Result<
        Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
        TransportError,
    > {
        let dispatched = {
            let mut guard = self.endpoint.lock().await;
            guard.accept_channel().await
        };

        let (header, mut quic_reader, mut quic_writer) = match dispatched {
            Some(stream) => stream,
            None => return Ok(None),
        };

        let (from_client_tx, from_client_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) = remoc::rch::mpsc::channel(64);
        let (to_client_tx, to_client_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) = remoc::rch::mpsc::channel(64);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = match quic_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if from_client_tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        }.in_current_span());

        tokio::spawn(async move {
            let mut to_client_rx = to_client_rx;
            while let Ok(Some(data)) = to_client_rx.recv().await {
                if quic_writer.write_all(&data).await.is_err() {
                    break;
                }
                if quic_writer.flush().await.is_err() {
                    break;
                }
            }
            let _ = quic_writer.shutdown().await;
        }.in_current_span());

        Ok(Some((header, from_client_rx, to_client_tx)))
    }

    async fn open_channel(
        &self,
        header: Option<ChannelHeader>,
    ) -> Result<
        (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
        TransportError,
    > {
            let (quic_reader, mut quic_writer) = {
            let guard = self.endpoint.lock().await;
            guard
                .open_stream()
                .await
                .map_err(|_| TransportError::OpenFailed("failed to open stream".into()))?
        };

        if let Some(h) = &header {
            quic_writer.encode_one(h)
                .await
                .map_err(|_| TransportError::OpenFailed("failed to write channel header".into()))?;
            quic_writer
                .flush()
                .await
                .map_err(|_| TransportError::OpenFailed("failed to flush channel header".into()))?;
        }

        let (from_remote_tx, from_remote_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) = remoc::rch::mpsc::channel(64);
        let (to_remote_tx, to_remote_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) = remoc::rch::mpsc::channel(64);

        tokio::spawn(async move {
            let mut quic_reader = quic_reader;
            let mut buf = vec![0u8; 8192];
            loop {
                let n = match quic_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if from_remote_tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
        }.in_current_span());

        tokio::spawn(async move {
            let mut to_remote_rx = to_remote_rx;
            while let Ok(Some(data)) = to_remote_rx.recv().await {
                if quic_writer.write_all(&data).await.is_err() {
                    break;
                }
                if quic_writer.flush().await.is_err() {
                    break;
                }
            }
            let _ = quic_writer.shutdown().await;
        }.in_current_span());

        Ok((from_remote_rx, to_remote_tx))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::reverse_tcp::ReverseTcpForwarder;
    use crate::forward::streamlocal::ReverseStreamlocalForwarder;
    use genmeta_ssh::ChannelEvent;
    use genmeta_ssh::{DEFAULT_MAX_MESSAGE_SIZE, codec::ChannelHeader, message::SshMessage, open_session_channel};
    use genmeta_ssh::{CancelTcpipForwardRequest, TcpipForwardRequest};
    use genmeta_ssh::{Ssh3Transport as RemoteSessionTransport, Ssh3TransportClient, Ssh3TransportServerShared, TransportError};
    use h3x::codec::{DecodeFrom, EncodeInto};
    use h3x::stream_id::StreamId;
    use remoc::rtc::ServerShared;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering as AtomicOrdering}};
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
                assert_eq!(max_message_size, VarInt::from(DEFAULT_MAX_MESSAGE_SIZE as u32));
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

        handle_channel(header, server_reader, server_writer)
            .await
            .unwrap();

        // Read the ChannelOpenFailure from the server
        let failure = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match failure {
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(reason_code, VarInt::from(3u8), "reason_code should be 3 (unknown channel type)");
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
        // After T8, non-session channel types with no session_client are treated
        // as unknown and get ChannelOpenFailure (same as unknown_channel_type).
        let forwarding_types = [
            "forwarded-tcpip",
            "forwarded-streamlocal@openssh.com",
        ];

        for channel_type in forwarding_types {
            let (_, server_reader) = duplex(8192);
            let (server_writer, mut client_reader) = duplex(8192);

            let header = ChannelHeader {
                signal_value: 0xaf3627e6,
                conversation_id: 1,
                channel_type: channel_type.into(),
                max_message_size: 65536,
            };

            let result = handle_channel(header, server_reader, server_writer).await;
            assert!(
                result.is_ok(),
                "forwarding type {channel_type} should return Ok()"
            );

            // Should receive ChannelOpenFailure since no session_client.
            let failure = SshMessage::decode_from(&mut client_reader).await.unwrap();
            assert!(
                matches!(failure, SshMessage::ChannelOpenFailure { reason_code, .. } if reason_code == VarInt::from(3u8)),
                "expected ChannelOpenFailure for {channel_type}, got {failure:?}"
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
                data_type: VarInt::from(1u8), // stderr
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
                data_type: VarInt::from(1u8),
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

    // -----------------------------------------------------------------------
    // Test 10: ConversationEndpoint basic functionality
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn conversation_endpoint_accept_channel() {
        let (tx, rx) = mpsc::channel(8);
        let opener: OpenBiFactory = Arc::new(|| {
            Box::pin(async {
                Err(io::Error::new(io::ErrorKind::Unsupported, "not used in test"))
            })
        });
        let mut endpoint = ConversationEndpoint::new(StreamId(VarInt::from(42u8)), rx, opener);
        assert_eq!(endpoint.conversation_id(), StreamId(VarInt::from(42u8)));

        // Drop sender — accept_channel should return None.
        drop(tx);
        assert!(endpoint.accept_channel().await.is_none());
    }

    #[tokio::test]
    async fn transport_open_channel_without_working_opener_fails() {
        let (_tx, rx) = mpsc::channel(8);
        let opener: OpenBiFactory = Arc::new(|| {
            Box::pin(async {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "test opener failed"))
            })
        });
        let endpoint = ConversationEndpoint::new(StreamId(VarInt::from(7u8)), rx, opener);
        let transport = Ssh3Transport::new(endpoint);
        let result = transport.open_channel(None).await;
        assert!(matches!(result, Err(TransportError::OpenFailed(_))));
    }

    struct TestTransport;

    impl RemoteSessionTransport for TestTransport {
        async fn accept_channel(&self) -> Result<
            Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
            TransportError,
        > {
            let (tx, rx) = remoc::rch::mpsc::channel(16);
            Ok((rx, tx))
        }
    }

    fn test_transport_client() -> Ssh3TransportClient {
        let (server, client) = Ssh3TransportServerShared::new(Arc::new(TestTransport), 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    fn global_request_context() -> Arc<GlobalRequestContext> {
        Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::new()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::new()),
            transport: test_transport_client(),
            conversation_id: StreamId::try_from(1u64).unwrap(),
        })
    }

    #[tokio::test]
    async fn global_request_tcpip_forward_rejects_out_of_range_port() {
        let (client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);
        let ctx = global_request_context();

        let server_handle = tokio::spawn(async move {
            handle_global_request_channel(server_reader, server_writer, Some(ctx))
                .await
                .unwrap();
        });

        let mut client_writer = client_writer;
        let mut request_data = Vec::new();
        request_data
            .encode_one(&TcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: u16::MAX as u32 + 1,
            })
            .await
            .unwrap();
        SshMessage::GlobalRequest {
            request_type: "tcpip-forward".into(),
            want_reply: true,
            data: request_data,
        }
        .encode_into(&mut client_writer)
        .await
        .unwrap();
        drop(client_writer);

        let reply = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(reply, SshMessage::RequestFailure));

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn global_request_cancel_tcpip_forward_rejects_out_of_range_port() {
        let (client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);
        let ctx = global_request_context();

        let server_handle = tokio::spawn(async move {
            handle_global_request_channel(server_reader, server_writer, Some(ctx))
                .await
                .unwrap();
        });

        let mut client_writer = client_writer;
        let mut request_data = Vec::new();
        request_data
            .encode_one(&CancelTcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: u16::MAX as u32 + 1,
            })
            .await
            .unwrap();
        SshMessage::GlobalRequest {
            request_type: "cancel-tcpip-forward".into(),
            want_reply: true,
            data: request_data,
        }
        .encode_into(&mut client_writer)
        .await
        .unwrap();
        drop(client_writer);

        let reply = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(reply, SshMessage::RequestFailure));

        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn global_request_control_stream_pre_readiness_rejects_without_handler_dispatch() {
        let (mut client_writer, mut server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);
        let readiness = StdArc::new(AtomicBool::new(false));
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_for_handler = Arc::clone(&handler_calls);
        let handler = move |_request_type, _data, _global_ctx| {
            let handler_calls = Arc::clone(&handler_calls_for_handler);
            async move {
                handler_calls.fetch_add(1, AtomicOrdering::SeqCst);
                Ok(GlobalRequestReply::Success(b"ok".to_vec()))
            }
        };

        let readiness_for_server = StdArc::clone(&readiness);
        let server_task = tokio::spawn(async move {
            serve_control_stream_global_requests_with_handler(
                &mut server_reader,
                server_writer,
                readiness_for_server,
                None,
                handler,
            )
            .await
            .unwrap();
        });

        SshMessage::GlobalRequest {
            request_type: "tcpip-forward".into(),
            want_reply: true,
            data: vec![],
        }
        .encode_into(&mut client_writer)
        .await
        .unwrap();

        let rejected = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            SshMessage::decode_from(&mut client_reader),
        )
        .await
        .expect("pre-readiness rejection should arrive before deadline")
        .unwrap();
        assert!(matches!(rejected, SshMessage::RequestFailure));
        assert_eq!(handler_calls.load(AtomicOrdering::SeqCst), 0);

        readiness.store(true, Ordering::SeqCst);
        SshMessage::GlobalRequest {
            request_type: "tcpip-forward".into(),
            want_reply: true,
            data: vec![],
        }
        .encode_into(&mut client_writer)
        .await
        .unwrap();
        client_writer.shutdown().await.unwrap();

        let accepted = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            SshMessage::decode_from(&mut client_reader),
        )
        .await
        .expect("post-readiness reply should arrive before deadline")
        .unwrap();
        assert_eq!(accepted, SshMessage::RequestSuccess { data: b"ok".to_vec() });
        assert_eq!(handler_calls.load(AtomicOrdering::SeqCst), 1);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn global_request_control_stream_sequential_requests_preserve_reply_order() {
        let (mut client_writer, mut server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);
        let readiness = StdArc::new(AtomicBool::new(true));
        let handler = move |request_type: String, _data: Vec<u8>, _global_ctx: Option<Arc<GlobalRequestContext>>| async move {
            Ok(GlobalRequestReply::Success(request_type.into_bytes()))
        };

        let server_task = tokio::spawn(async move {
            serve_control_stream_global_requests_with_handler(
                &mut server_reader,
                server_writer,
                readiness,
                None,
                handler,
            )
            .await
            .unwrap();
        });

        for request_type in ["first", "second"] {
            SshMessage::GlobalRequest {
                request_type: request_type.into(),
                want_reply: true,
                data: vec![],
            }
            .encode_into(&mut client_writer)
            .await
            .unwrap();

            let reply = SshMessage::decode_from(&mut client_reader).await.unwrap();
            assert_eq!(
                reply,
                SshMessage::RequestSuccess {
                    data: request_type.as_bytes().to_vec(),
                }
            );
        }

        client_writer.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn global_request_control_stream_second_in_flight_request_rejected_before_handler_runs() {
        let (mut client_writer, mut server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);
        let readiness = StdArc::new(AtomicBool::new(true));
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let release_rx_for_handler = Arc::clone(&release_rx);
        let handler_calls_for_handler = Arc::clone(&handler_calls);
        let handler = move |request_type: String, _data: Vec<u8>, _global_ctx: Option<Arc<GlobalRequestContext>>| {
            let release_rx = Arc::clone(&release_rx_for_handler);
            let handler_calls = Arc::clone(&handler_calls_for_handler);
            async move {
                handler_calls.fetch_add(1, AtomicOrdering::SeqCst);
                if request_type == "first"
                    && let Some(rx) = release_rx.lock().await.take()
                {
                    let _ = rx.await;
                }
                Ok(GlobalRequestReply::Success(request_type.into_bytes()))
            }
        };

        let server_task = tokio::spawn(async move {
            serve_control_stream_global_requests_with_handler(
                &mut server_reader,
                server_writer,
                readiness,
                None,
                handler,
            )
            .await
            .unwrap();
        });

        SshMessage::GlobalRequest {
            request_type: "first".into(),
            want_reply: true,
            data: vec![],
        }
        .encode_into(&mut client_writer)
        .await
        .unwrap();
        SshMessage::GlobalRequest {
            request_type: "second".into(),
            want_reply: true,
            data: vec![],
        }
        .encode_into(&mut client_writer)
        .await
        .unwrap();

        let rejected = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            SshMessage::decode_from(&mut client_reader),
        )
        .await
        .expect("second in-flight request should be rejected before deadline")
        .unwrap();
        assert!(matches!(rejected, SshMessage::RequestFailure));
        assert_eq!(handler_calls.load(AtomicOrdering::SeqCst), 1);

        release_tx.send(()).unwrap();

        let first_reply = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            SshMessage::decode_from(&mut client_reader),
        )
        .await
        .expect("first request should eventually complete")
        .unwrap();
        assert_eq!(
            first_reply,
            SshMessage::RequestSuccess {
                data: b"first".to_vec(),
            }
        );

        client_writer.shutdown().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn global_request_legacy_channel_rejection_is_explicit() {
        let (_client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let server_task = tokio::spawn(async move {
            reject_legacy_global_request_channel(server_writer).await.unwrap();
            drop(server_reader);
        });

        let reply = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match reply {
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(reason_code, VarInt::from(3u8));
                assert!(description.contains("control stream"));
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }

        server_task.await.unwrap();
    }
}
