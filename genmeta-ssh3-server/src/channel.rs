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
use genmeta_ssh3_proto::session::{Ssh3Transport, TransportError};
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
pub async fn handle_global_request_channel<R, W>(
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

/// Handle an open-channel request from the child process.
///
/// Opens a new QUIC bidirectional stream via `stream_factory`, optionally
/// writes the `ChannelHeader`, creates byte bridges, and returns remoc
/// channel endpoints to the child.
pub async fn handle_open_channel_request(
    header: Option<ChannelHeader>,
    stream_factory: &forward::StreamFactory,
) -> Result<
    (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
    genmeta_ssh3_proto::session::SessionError,
> {
    use genmeta_ssh3_proto::session::SessionError;

    // 1. Open a new QUIC bidirectional stream.
    let (quic_reader, mut quic_writer) = stream_factory()
        .await
        .map_err(|e| SessionError::new(e.to_string()))?;

    // 2. Write ChannelHeader if provided; skip if None (caller writes its own data).
    if let Some(h) = &header {
        h.encode_into(&mut quic_writer)
            .await
            .map_err(|e| SessionError::new(e.to_string()))?;
        quic_writer
            .flush()
            .await
            .map_err(|e| SessionError::new(e.to_string()))?;
    }

    // 3. Create remoc byte channel pairs for the child.
    let (from_remote_tx, from_remote_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) = remoc::rch::mpsc::channel(64);
    let (to_remote_tx, to_remote_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) = remoc::rch::mpsc::channel(64);

    // 4. Spawn byte bridge: QUIC reader → from_remote_tx
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
    });

    // 5. Spawn byte bridge: to_remote_rx → QUIC writer
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
    });

    // 6. Return remoc endpoints to child.
    Ok((from_remote_rx, to_remote_tx))
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
// ConversationHandle — raw QUIC-level handle for a fully-activated conversation
// ---------------------------------------------------------------------------

/// A fully-activated conversation handle.
///
/// Created by [`ReservedConversation::activate()`]. Encapsulates the
/// conversation ID, the receiver for dispatched QUIC streams, and the
/// optional stream factory for opening server-initiated streams.
///
/// This is the raw QUIC-level handle. The remoc bridging layer lives in
/// [`Ssh3TransportImpl`], which will consume this handle in Phase 5.
pub struct ConversationHandle {
    conversation_id: u64,
    channel_rx: mpsc::Receiver<DispatchedStream>,
    stream_factory: Option<forward::StreamFactory>,
}

impl ConversationHandle {
    pub(crate) fn new(
        conversation_id: u64,
        channel_rx: mpsc::Receiver<DispatchedStream>,
        stream_factory: Option<forward::StreamFactory>,
    ) -> Self {
        Self { conversation_id, channel_rx, stream_factory }
    }

    /// Returns the conversation ID (u64 from the QUIC stream ID).
    pub fn conversation_id(&self) -> u64 {
        self.conversation_id
    }

    /// Accept the next dispatched channel stream from the remote peer.
    ///
    /// Returns `None` when the conversation is closed (sender dropped).
    pub async fn accept_channel(&mut self) -> Option<DispatchedStream> {
        self.channel_rx.recv().await
    }

    /// Open a new server-initiated QUIC bidirectional stream.
    ///
    /// Writes the `ChannelHeader` to the stream if provided.
    /// Returns raw `AsyncRead`/`AsyncWrite` streams (no remoc bridging).
    pub async fn open_channel(
        &self,
        header: Option<ChannelHeader>,
    ) -> io::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let sf = self.stream_factory.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no stream factory available")
        })?;
        let (reader, mut writer) = sf().await?;
        if let Some(h) = &header {
            h.encode_into(&mut writer).await?;
            writer.flush().await?;
        }
        Ok((reader, writer))
    }
}

// ---------------------------------------------------------------------------
// Ssh3TransportImpl — parent-process transport bridging QUIC ↔ remoc channels
// ---------------------------------------------------------------------------

/// Parent-process transport that bridges QUIC streams to remoc byte channels.
///
/// Implements [`Ssh3Transport`] for use as the RTC server object provided to
/// the child process. Incoming QUIC streams are accepted from the
/// [`ConversationHandle`]; outgoing streams are opened via its stream factory.
///
/// Supports a **pending/attach** pattern: construct with [`new_pending`] before
/// authentication completes, then call [`attach_handle`] once the
/// [`ConversationHandle`] is available. `accept_channel` will block until
/// `attach_handle` is called.
pub struct Ssh3TransportImpl {
    handle: tokio::sync::Mutex<Option<ConversationHandle>>,
    attached: tokio::sync::watch::Receiver<bool>,
    attached_tx: tokio::sync::watch::Sender<bool>,
}

impl Ssh3TransportImpl {
    /// Create a transport with a known handle (used in tests and child.rs).
    pub fn new(handle: ConversationHandle) -> Self {
        let (attached_tx, attached) = tokio::sync::watch::channel(true);
        Self {
            handle: tokio::sync::Mutex::new(Some(handle)),
            attached,
            attached_tx,
        }
    }

    /// Create a **pending** transport without a handle.
    ///
    /// Neither `accept_channel` nor `open_channel` will work until
    /// [`attach_handle`](Self::attach_handle) is called.
    pub fn new_pending() -> Self {
        let (attached_tx, attached) = tokio::sync::watch::channel(false);
        Self {
            handle: tokio::sync::Mutex::new(None),
            attached,
            attached_tx,
        }
    }

    /// Attach a [`ConversationHandle`] to this transport, unblocking
    /// `accept_channel` and `open_channel`.
    pub fn attach_handle(&self, handle: ConversationHandle) {
        {
            let mut guard = self.handle.try_lock()
                .expect("attach_handle called while handle lock is held");
            *guard = Some(handle);
        }
        let _ = self.attached_tx.send(true);
    }
}

impl Ssh3Transport for Ssh3TransportImpl {
    async fn accept_channel(&self) -> Result<
        Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
        TransportError,
    > {
        // Wait until the handle is attached (no-op if already attached via `new`).
        {
            let mut attached = self.attached.clone();
            // wait_for resolves immediately if already true.
            let _ = attached.wait_for(|&v| v).await;
        }

        let dispatched = {
            let mut guard = self.handle.lock().await;
            let handle = match guard.as_mut() {
                Some(h) => h,
                None => return Ok(None),
            };
            handle.accept_channel().await
        };

        let (header, mut quic_reader, mut quic_writer) = match dispatched {
            Some(stream) => stream,
            None => return Ok(None),
        };

        // Create remoc byte channel pairs for the child process.
        let (from_client_tx, from_client_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) = remoc::rch::mpsc::channel(64);
        let (to_client_tx, to_client_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) = remoc::rch::mpsc::channel(64);

        // Bridge: QUIC reader → from_client_tx (raw bytes to child)
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
        });

        // Bridge: to_client_rx → QUIC writer (raw bytes from child)
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
        });

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
            let guard = self.handle.lock().await;
            let handle = guard.as_ref().ok_or_else(|| {
                TransportError::OpenFailed("no handle attached".into())
            })?;
            handle.open_channel(None).await
                .map_err(|e| TransportError::OpenFailed(e.to_string()))?
        };

        // Write ChannelHeader if provided.
        if let Some(h) = &header {
            h.encode_into(&mut quic_writer)
                .await
                .map_err(|e| TransportError::OpenFailed(e.to_string()))?;
            quic_writer
                .flush()
                .await
                .map_err(|e| TransportError::OpenFailed(e.to_string()))?;
        }

        // Create remoc byte channel pairs for the child.
        let (from_remote_tx, from_remote_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) = remoc::rch::mpsc::channel(64);
        let (to_remote_tx, to_remote_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) = remoc::rch::mpsc::channel(64);

        // Bridge: QUIC reader → from_remote_tx
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
        });

        // Bridge: to_remote_rx → QUIC writer
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
        });

        Ok((from_remote_rx, to_remote_tx))
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
                matches!(failure, SshMessage::ChannelOpenFailure { reason_code: 3, .. }),
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

    // -----------------------------------------------------------------------
    // Test 10: ConversationHandle basic functionality
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn conversation_handle_accept_channel() {
        let (tx, rx) = mpsc::channel(8);
        let mut handle = ConversationHandle::new(42, rx, None);
        assert_eq!(handle.conversation_id(), 42);

        // Drop sender — accept_channel should return None.
        drop(tx);
        assert!(handle.accept_channel().await.is_none());
    }

    #[tokio::test]
    async fn conversation_handle_open_channel_no_factory() {
        let (_tx, rx) = mpsc::channel(8);
        let handle = ConversationHandle::new(99, rx, None);
        assert_eq!(handle.conversation_id(), 99);

        // open_channel without a stream factory should fail.
        let result = handle.open_channel(None).await;
        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotConnected),
            Ok(_) => panic!("expected NotConnected error, got Ok"),
        }
    }
}
