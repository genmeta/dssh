//! SSH3 session types and transport trait for cross-process communication.
//!
//! The [`Ssh3Transport`] trait is marked with `#[remoc::rtc::remote]`, which generates:
//! - [`Ssh3TransportClient`] — serializable proxy sent to the child process
//! - [`Ssh3TransportServer`] / [`Ssh3TransportServerShared`] / [`Ssh3TransportServerSharedMut`] —
//!   wrappers for serving the trait implementation
//!
//! The main server process implements the trait and serves it; the child
//! process uses the client to accept and open channels.

use std::{
    future::Future,
    path::PathBuf,
    pin::{Pin, pin},
};

use crate::{
    channel::{ChannelMessage, ChannelRequest},
    codec::{CodecError, SshBool, SshBytes, SshString},
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::{EmptyPayload, NotifyChannelRequest, WantReplyChannelRequest},
    message::{MessageError, SshMessage},
};
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use snafu::{ResultExt, Snafu};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tracing::Instrument;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum SessionCodecError {
    #[snafu(display("session codec failed"))]
    Codec { source: CodecError },

    #[snafu(display("session stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("session stream write failed"))]
    WriteIo { source: std::io::Error },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum SessionProtocolError {
    #[snafu(display("session message codec failed"))]
    Message { source: MessageError },

    #[snafu(display("session operation failed while {operation}"))]
    Io {
        operation: &'static str,
        source: std::io::Error,
    },

    #[snafu(display("session stream write failed"))]
    WriteIo { source: std::io::Error },

    #[snafu(display("session stream shutdown failed"))]
    ShutdownIo { source: std::io::Error },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    Exec(SshBytes),
    Shell,
    AllocatePty(PtyRequest, SshBool),
    WindowChange(WindowChangeRequest),
    Signal(SignalRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLoopAction {
    Request(RequestAction),
    Eof,
    Close,
    Ignore,
}

pub async fn handle_request<W>(
    request: ChannelRequest,
    writer: &mut W,
) -> Result<Option<RequestAction>, SessionProtocolError>
where
    W: AsyncWrite + Send + Unpin,
{
    match request {
        ChannelRequest::Exec {
            want_reply,
            request,
        } => {
            if want_reply.0 {
                writer
                    .encode_one(SshMessage::Channel(ChannelMessage::Success))
                    .await
                    .context(session_protocol_error::MessageSnafu)?;
            }
            Ok(Some(RequestAction::Exec(request.command.clone())))
        }
        ChannelRequest::Shell { want_reply } => {
            if want_reply.0 {
                writer
                    .encode_one(SshMessage::Channel(ChannelMessage::Success))
                    .await
                    .context(session_protocol_error::MessageSnafu)?;
            }
            Ok(Some(RequestAction::Shell))
        }
        ChannelRequest::PtyReq {
            want_reply,
            request,
        } => Ok(Some(RequestAction::AllocatePty(request.clone(), want_reply.clone()))),
        ChannelRequest::WindowChange(request) => Ok(Some(RequestAction::WindowChange(request.clone()))),
        ChannelRequest::Signal {
            want_reply,
            request,
        } => {
            if want_reply.0 {
                writer
                    .encode_one(SshMessage::Channel(ChannelMessage::Success))
                    .await
                    .context(session_protocol_error::MessageSnafu)?;
            }
            Ok(Some(RequestAction::Signal(request.clone())))
        }
        ChannelRequest::Subsystem { want_reply, .. } => {
            if want_reply.0 {
                writer
                    .encode_one(SshMessage::Channel(ChannelMessage::Failure))
                    .await
                    .context(session_protocol_error::MessageSnafu)?;
            }
            Ok(None)
        }
        ChannelRequest::ExitStatus(_) | ChannelRequest::ExitSignal(_) => Ok(None),
        ChannelRequest::Unknown { want_reply, .. } => {
            if want_reply.0 {
                writer
                    .encode_one(SshMessage::Channel(ChannelMessage::Failure))
                    .await
                    .context(session_protocol_error::MessageSnafu)?;
            }
            Ok(None)
        }
    }
}

pub async fn handle_session_loop_message<W>(
    message: ChannelMessage,
    writer: &mut W,
) -> Result<SessionLoopAction, SessionProtocolError>
where
    W: AsyncWrite + Send + Unpin,
{
    match message {
        ChannelMessage::Request(request) => Ok(match handle_request(request, writer).await? {
            Some(action) => SessionLoopAction::Request(action),
            None => SessionLoopAction::Ignore,
        }),
        ChannelMessage::Eof => {
            writer
                .encode_one(SshMessage::Channel(ChannelMessage::Eof))
                .await
                .context(session_protocol_error::MessageSnafu)?;
            writer
                .shutdown()
                .await
                .context(session_protocol_error::ShutdownIoSnafu)?;
            Ok(SessionLoopAction::Eof)
        }
        ChannelMessage::Close => {
            writer
                .encode_one(SshMessage::Channel(ChannelMessage::Close))
                .await
                .context(session_protocol_error::MessageSnafu)?;
            Ok(SessionLoopAction::Close)
        }
        ChannelMessage::Data(_) | ChannelMessage::ExtendedData { .. } => Ok(SessionLoopAction::Ignore),
        ChannelMessage::OpenConfirmation { .. }
        | ChannelMessage::OpenFailure(_)
        | ChannelMessage::Success
        | ChannelMessage::Failure => Ok(SessionLoopAction::Ignore),
    }
}

/// Information needed to initialize an SSH3 session in the child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInit {
    /// Unique conversation identifier for this session.
    #[serde(
        serialize_with = "serialize_stream_id",
        deserialize_with = "deserialize_stream_id"
    )]
    pub conversation_id: StreamId,
    /// Authenticated username.
    pub username: String,
    /// POSIX user ID.
    pub uid: u32,
    /// POSIX group ID.
    pub gid: u32,
    /// User's home directory.
    pub home: PathBuf,
    /// User's login shell.
    pub shell: PathBuf,
}

/// Result of PAM authentication performed by the main process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthResult {
    /// Authentication succeeded.
    Success {
        /// POSIX user ID.
        uid: u32,
        /// POSIX group ID.
        gid: u32,
        /// User's home directory.
        home: PathBuf,
        /// User's login shell.
        shell: PathBuf,
    },
    /// Authentication failed.
    Failure {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

/// Bootstrap payload sent from parent to child process.
/// Contains the transport client for pulling channels and the credential for PAM auth.
#[derive(Serialize, Deserialize)]
pub struct ChildBootstrap {
    pub transport: Ssh3TransportClient,
    pub credential: crate::auth::AuthCredential,
    #[serde(
        serialize_with = "serialize_stream_id",
        deserialize_with = "deserialize_stream_id"
    )]
    pub conversation_id: StreamId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: SshBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemRequest {
    pub subsystem_name: SshString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatusRequest {
    pub exit_status: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignalRequest {
    pub signal_name: SshString,
    pub core_dumped: SshBool,
    pub error_message: SshString,
    pub language_tag: SshString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    pub term_type: SshString,
    pub width_cols: VarInt,
    pub height_rows: VarInt,
    pub width_px: VarInt,
    pub height_px: VarInt,
    pub terminal_modes: SshBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowChangeRequest {
    pub width_cols: VarInt,
    pub height_rows: VarInt,
    pub width_px: VarInt,
    pub height_px: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalRequest {
    pub signal_name: SshString,
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExecRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            command: stream.decode_one().await.context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ExecRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.command).await.context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SubsystemRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            subsystem_name: stream.decode_one().await.context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for SubsystemRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.subsystem_name)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitStatusRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let exit_status: VarInt = stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?;
        Ok(Self { exit_status })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ExitStatusRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.exit_status).await.context(session_codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitSignalRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let signal_name: SshString = stream.decode_one().await.context(session_codec_error::CodecSnafu)?;
        let core_dumped: SshBool = stream.decode_one().await.context(session_codec_error::CodecSnafu)?;
        let error_message: SshString = stream.decode_one().await.context(session_codec_error::CodecSnafu)?;
        let language_tag: SshString = stream.decode_one().await.context(session_codec_error::CodecSnafu)?;
        Ok(Self {
            signal_name,
            core_dumped,
            error_message,
            language_tag,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ExitSignalRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.signal_name).await.context(session_codec_error::CodecSnafu)?;
        stream.encode_one(self.core_dumped).await.context(session_codec_error::CodecSnafu)?;
        stream.encode_one(self.error_message).await.context(session_codec_error::CodecSnafu)?;
        stream.encode_one(self.language_tag).await.context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for PtyRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            term_type: stream.decode_one().await.context(session_codec_error::CodecSnafu)?,
            width_cols: stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?,
            height_rows: stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?,
            width_px: stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?,
            height_px: stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?,
            terminal_modes: stream.decode_one().await.context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for PtyRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.term_type).await.context(session_codec_error::CodecSnafu)?;
        stream.encode_one(self.width_cols).await.context(session_codec_error::WriteIoSnafu)?;
        stream.encode_one(self.height_rows).await.context(session_codec_error::WriteIoSnafu)?;
        stream.encode_one(self.width_px).await.context(session_codec_error::WriteIoSnafu)?;
        stream.encode_one(self.height_px).await.context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.terminal_modes)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for WindowChangeRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let width_cols: VarInt = stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?;
        let height_rows: VarInt = stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?;
        let width_px: VarInt = stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?;
        let height_px: VarInt = stream.decode_one().await.context(session_codec_error::ReadIoSnafu)?;
        Ok(Self {
            width_cols,
            height_rows,
            width_px,
            height_px,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for WindowChangeRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.width_cols).await.context(session_codec_error::WriteIoSnafu)?;
        stream.encode_one(self.height_rows).await.context(session_codec_error::WriteIoSnafu)?;
        stream.encode_one(self.width_px).await.context(session_codec_error::WriteIoSnafu)?;
        stream.encode_one(self.height_px).await.context(session_codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SignalRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            signal_name: stream.decode_one().await.context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for SignalRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.signal_name).await.context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

// ===========================================================================
// WantReplyChannelRequest / NotifyChannelRequest implementations
// ===========================================================================

/// Channel request `"pty-req"` — allocate a pseudo-terminal.
#[derive(Debug, Clone)]
pub struct PtyChannelRequest {
    pub payload: PtyRequest,
}

impl WantReplyChannelRequest for PtyChannelRequest {
    type Success = EmptyPayload;
    type Payload = PtyRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("pty-req")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel request `"exec"` — execute a command.
#[derive(Debug, Clone)]
pub struct ExecChannelRequest {
    pub payload: ExecRequest,
}

impl WantReplyChannelRequest for ExecChannelRequest {
    type Success = EmptyPayload;
    type Payload = ExecRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("exec")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel request `"shell"` — start an interactive shell.
#[derive(Debug, Clone)]
pub struct ShellChannelRequest;

impl WantReplyChannelRequest for ShellChannelRequest {
    type Success = EmptyPayload;
    type Payload = EmptyPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("shell")
    }

    fn payload(&self) -> &Self::Payload {
        &EmptyPayload
    }
}

/// Channel request `"subsystem"` — start a subsystem.
#[derive(Debug, Clone)]
pub struct SubsystemChannelRequest {
    pub payload: SubsystemRequest,
}

impl WantReplyChannelRequest for SubsystemChannelRequest {
    type Success = EmptyPayload;
    type Payload = SubsystemRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("subsystem")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel request `"signal"` — send a signal to the remote process.
#[derive(Debug, Clone)]
pub struct SignalChannelRequest {
    pub payload: SignalRequest,
}

impl WantReplyChannelRequest for SignalChannelRequest {
    type Success = EmptyPayload;
    type Payload = SignalRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("signal")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"signal"` — send signal without expecting reply.
#[derive(Debug, Clone)]
pub struct SignalChannelNotice {
    pub payload: SignalRequest,
}

impl NotifyChannelRequest for SignalChannelNotice {
    type Payload = SignalRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("signal")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"window-change"` — terminal size changed (no reply).
#[derive(Debug, Clone)]
pub struct WindowChangeChannelNotice {
    pub payload: WindowChangeRequest,
}

impl NotifyChannelRequest for WindowChangeChannelNotice {
    type Payload = WindowChangeRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("window-change")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"exit-status"` — process exited (no reply).
#[derive(Debug, Clone)]
pub struct ExitStatusChannelNotice {
    pub payload: ExitStatusRequest,
}

impl NotifyChannelRequest for ExitStatusChannelNotice {
    type Payload = ExitStatusRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("exit-status")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"exit-signal"` — process killed by signal (no reply).
#[derive(Debug, Clone)]
pub struct ExitSignalChannelNotice {
    pub payload: ExitSignalRequest,
}

impl NotifyChannelRequest for ExitSignalChannelNotice {
    type Payload = ExitSignalRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("exit-signal")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

pub fn encode_exit_status(exit_code: u32) -> Vec<u8> {
    let v = exit_code as u64;
    if v < 64 {
        vec![v as u8]
    } else if v < 16384 {
        vec![0x40 | ((v >> 8) as u8), (v & 0xff) as u8]
    } else if v < 1_073_741_824 {
        let val = 0x80000000u32 | (v as u32);
        val.to_be_bytes().to_vec()
    } else {
        let val = 0xC000_0000_0000_0000u64 | v;
        val.to_be_bytes().to_vec()
    }
}

pub async fn open_session_channel<R, W>(
    reader: R,
    mut writer: W,
) -> Result<(mpsc::Receiver<ChannelMessage>, W), SessionProtocolError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let confirm = SshMessage::Channel(ChannelMessage::OpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    });
    writer
        .encode_one(confirm)
        .await
        .context(session_protocol_error::MessageSnafu)?;

    let (event_tx, event_rx) = mpsc::channel(64);
    tokio::spawn(
        async move {
            let _ = run_message_loop_with_sender(reader, event_tx).await;
        }
        .in_current_span(),
    );
    Ok((event_rx, writer))
}

pub async fn run_session_request_loop<W, S, ExecFn, ShellFn, PtyFn, ResizeFn, SignalFn>(
    mut event_rx: mpsc::Receiver<ChannelMessage>,
    mut writer: W,
    mut state: S,
    mut allocate_pty: PtyFn,
    mut set_window_size: ResizeFn,
    mut run_exec: ExecFn,
    mut run_shell: ShellFn,
    mut on_signal: SignalFn,
 ) -> Result<(), SessionProtocolError>
where
    W: AsyncWrite + Send + Unpin + 'static,
    ExecFn: for<'a> FnMut(
        SshBytes,
        &'a mut W,
        mpsc::Receiver<ChannelMessage>,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
    ShellFn: for<'a> FnMut(
        &'a mut W,
        mpsc::Receiver<ChannelMessage>,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
    PtyFn: for<'a> FnMut(
        PtyRequest,
        SshBool,
        &'a mut W,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
    ResizeFn: for<'a> FnMut(
        WindowChangeRequest,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
    SignalFn: for<'a> FnMut(
        SignalRequest,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
{
    while let Some(message) = event_rx.recv().await {
        match handle_session_loop_message(message, &mut writer).await? {
            SessionLoopAction::Request(action) => match action {
                RequestAction::Exec(command) => {
                    run_exec(command, &mut writer, event_rx, &mut state)
                        .await
                        .context(session_protocol_error::IoSnafu {
                            operation: "running exec request",
                        })?;
                    return Ok(());
                }
                RequestAction::Shell => {
                    run_shell(&mut writer, event_rx, &mut state)
                        .await
                        .context(session_protocol_error::IoSnafu {
                            operation: "running shell request",
                        })?;
                    return Ok(());
                }
                RequestAction::AllocatePty(req, want_reply) => {
                    allocate_pty(req, want_reply, &mut writer, &mut state)
                        .await
                        .context(session_protocol_error::IoSnafu {
                            operation: "allocating pty",
                        })?;
                }
                RequestAction::WindowChange(req) => {
                    set_window_size(req, &mut state)
                        .await
                        .context(session_protocol_error::IoSnafu {
                            operation: "changing window size",
                        })?;
                }
                RequestAction::Signal(req) => on_signal(req, &mut state)
                    .await
                    .context(session_protocol_error::IoSnafu {
                        operation: "handling signal request",
                    })?,
            },
            SessionLoopAction::Eof | SessionLoopAction::Close => break,
            SessionLoopAction::Ignore => {}
        }
    }

    Ok(())
}

pub async fn run_message_loop_with_sender<R>(
    mut reader: R,
    event_tx: mpsc::Sender<ChannelMessage>,
) -> Result<(), SessionProtocolError>
where
    R: AsyncRead + Send + Unpin,
{
    loop {
        let msg = match reader.decode_one::<SshMessage>().await {
            Ok(msg) => msg,
            Err(MessageError::ReadIo {
                source,
            }) if source.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(e) => return Err(SessionProtocolError::Message { source: e }),
        };

        match msg {
            SshMessage::Channel(message @ ChannelMessage::Data(_))
            | SshMessage::Channel(message @ ChannelMessage::ExtendedData { .. })
            | SshMessage::Channel(message @ ChannelMessage::Request(_))
            | SshMessage::Channel(message @ ChannelMessage::Eof)
            | SshMessage::Channel(message @ ChannelMessage::Close) => {
                let is_close = matches!(message, ChannelMessage::Close);
                let _ = event_tx.send(message).await;
                if is_close {
                    return Ok(());
                }
            }
            SshMessage::Channel(ChannelMessage::Success) => {
                tracing::debug!("received ChannelSuccess(99)");
            }
            SshMessage::Channel(ChannelMessage::Failure) => {
                tracing::debug!("received ChannelFailure(100)");
            }
            other => {
                tracing::warn!("unexpected message in channel loop: {other:?}");
            }
        }
    }
}

fn serialize_stream_id<S>(stream_id: &StreamId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(stream_id.into_inner())
}

fn deserialize_stream_id<'de, D>(deserializer: D) -> Result<StreamId, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = u64::deserialize(deserializer)?;
    StreamId::try_from(raw).map_err(serde::de::Error::custom)
}

/// Serializable error type for RTC method returns.
///
/// This type crosses process boundaries via remoc, so it must be fully serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionError {
    Message(String),
    Io(IoErrorKind),
    Transport(TransportError),
    Remote(remoc::rtc::CallError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Io(kind) => kind.fmt(f),
            Self::Transport(error) => error.fmt(f),
            Self::Remote(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Remote(error) => Some(error),
            Self::Message(_) | Self::Io(_) => None,
        }
    }
}

impl From<remoc::rtc::CallError> for SessionError {
    fn from(err: remoc::rtc::CallError) -> Self {
        Self::Remote(err)
    }
}

impl From<std::io::Error> for SessionError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.kind().into())
    }
}

impl From<TransportError> for SessionError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
    }
}

impl SessionError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    Other,
}

impl std::fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NotFound => "not found",
            Self::PermissionDenied => "permission denied",
            Self::ConnectionRefused => "connection refused",
            Self::ConnectionReset => "connection reset",
            Self::HostUnreachable => "host unreachable",
            Self::NetworkUnreachable => "network unreachable",
            Self::ConnectionAborted => "connection aborted",
            Self::NotConnected => "not connected",
            Self::AddrInUse => "address in use",
            Self::AddrNotAvailable => "address not available",
            Self::NetworkDown => "network down",
            Self::BrokenPipe => "broken pipe",
            Self::AlreadyExists => "already exists",
            Self::WouldBlock => "operation would block",
            Self::InvalidInput => "invalid input",
            Self::InvalidData => "invalid data",
            Self::TimedOut => "timed out",
            Self::WriteZero => "write zero",
            Self::Interrupted => "interrupted",
            Self::Unsupported => "unsupported",
            Self::UnexpectedEof => "unexpected end of file",
            Self::OutOfMemory => "out of memory",
            Self::Other => "other I/O error",
        };
        f.write_str(name)
    }
}

impl From<std::io::ErrorKind> for IoErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            std::io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            std::io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            std::io::ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            std::io::ErrorKind::NotConnected => Self::NotConnected,
            std::io::ErrorKind::AddrInUse => Self::AddrInUse,
            std::io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            std::io::ErrorKind::NetworkDown => Self::NetworkDown,
            std::io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            std::io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            std::io::ErrorKind::WouldBlock => Self::WouldBlock,
            std::io::ErrorKind::InvalidInput => Self::InvalidInput,
            std::io::ErrorKind::InvalidData => Self::InvalidData,
            std::io::ErrorKind::TimedOut => Self::TimedOut,
            std::io::ErrorKind::WriteZero => Self::WriteZero,
            std::io::ErrorKind::Interrupted => Self::Interrupted,
            std::io::ErrorKind::Unsupported => Self::Unsupported,
            std::io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            std::io::ErrorKind::OutOfMemory => Self::OutOfMemory,
            _ => Self::Other,
        }
    }
}

/// Serializable error type for transport-level RTC method returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportError {
    ChannelClosed(String),
    OpenFailed(String),
    Timeout,
    Other(String),
    Remote(remoc::rtc::CallError),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelClosed(msg) => f.write_str(msg),
            Self::OpenFailed(msg) => f.write_str(msg),
            Self::Timeout => write!(f, "timeout"),
            Self::Other(msg) => f.write_str(msg),
            Self::Remote(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Remote(error) => Some(error),
            Self::ChannelClosed(_) | Self::OpenFailed(_) | Self::Timeout | Self::Other(_) => None,
        }
    }
}

impl From<remoc::rtc::CallError> for TransportError {
    fn from(err: remoc::rtc::CallError) -> Self {
        Self::Remote(err)
    }
}

/// RTC trait for SSH3 transport-level channel management.
///
/// The `#[remoc::rtc::remote]` macro generates `Ssh3TransportClient`,
/// `Ssh3TransportServer`, `Ssh3TransportServerShared`, and `Ssh3TransportServerSharedMut`.
#[remoc::rtc::remote]
pub trait Ssh3Transport: Sync {
    /// Accept an incoming channel from the remote peer.
    ///
    /// Returns `Ok(None)` when no more channels will arrive (connection closed).
    async fn accept_channel(
        &self,
    ) -> Result<
        Option<(
            crate::channel::ChannelHeader,
            remoc::rch::mpsc::Receiver<Vec<u8>>,
            remoc::rch::mpsc::Sender<Vec<u8>>,
        )>,
        TransportError,
    >;

    /// Open a new channel toward the remote peer.
    ///
    /// If `header` is `None`, no header is written to the underlying stream.
    async fn open_channel(
        &self,
        header: Option<crate::channel::ChannelHeader>,
    ) -> Result<
        (
            remoc::rch::mpsc::Receiver<Vec<u8>>,
            remoc::rch::mpsc::Sender<Vec<u8>>,
        ),
        TransportError,
    >;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_init_roundtrip() {
        let init = SessionInit {
            conversation_id: StreamId::try_from(42u64).unwrap(),
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        };
        let json = serde_json::to_string(&init).unwrap();
        let decoded: SessionInit = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.conversation_id, StreamId::try_from(42u64).unwrap());
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.uid, 1000);
        assert_eq!(decoded.gid, 1000);
        assert_eq!(decoded.home, PathBuf::from("/home/alice"));
        assert_eq!(decoded.shell, PathBuf::from("/bin/bash"));
    }

    #[test]
    fn auth_result_success_roundtrip() {
        let result = AuthResult::Success {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/bob"),
            shell: PathBuf::from("/bin/zsh"),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: AuthResult = serde_json::from_str(&json).unwrap();
        match decoded {
            AuthResult::Success {
                uid,
                gid,
                home,
                shell,
            } => {
                assert_eq!(uid, 1000);
                assert_eq!(gid, 1000);
                assert_eq!(home, PathBuf::from("/home/bob"));
                assert_eq!(shell, PathBuf::from("/bin/zsh"));
            }
            AuthResult::Failure { .. } => panic!("expected Success"),
        }
    }

    #[test]
    fn auth_result_failure_roundtrip() {
        let result = AuthResult::Failure {
            reason: "invalid password".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: AuthResult = serde_json::from_str(&json).unwrap();
        match decoded {
            AuthResult::Failure { reason } => assert_eq!(reason, "invalid password"),
            AuthResult::Success { .. } => panic!("expected Failure"),
        }
    }

    #[test]
    fn session_error_display() {
        let err = SessionError::new("something went wrong");
        assert_eq!(err.to_string(), "something went wrong");
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn session_error_roundtrip() {
        let err = SessionError::new("test error");
        let json = serde_json::to_string(&err).unwrap();
        let decoded: SessionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err.to_string(), decoded.to_string());
    }

    #[test]
    fn ssh3_transport_client_type_exists() {
        fn assert_send<T: Send>() {}
        assert_send::<Ssh3TransportClient>();
    }

    #[test]
    fn ssh3_transport_server_types_exist() {
        // Ssh3TransportServerShared<T> requires a concrete impl type.
        // Create a trivial one to verify the generated type exists and is Send.
        struct Dummy;
        impl Ssh3Transport for Dummy {
            async fn accept_channel(
                &self,
            ) -> Result<
                Option<(
                    crate::channel::ChannelHeader,
                    remoc::rch::mpsc::Receiver<Vec<u8>>,
                    remoc::rch::mpsc::Sender<Vec<u8>>,
                )>,
                TransportError,
            > {
                Ok(None)
            }
            async fn open_channel(
                &self,
                _: Option<crate::channel::ChannelHeader>,
            ) -> Result<
                (
                    remoc::rch::mpsc::Receiver<Vec<u8>>,
                    remoc::rch::mpsc::Sender<Vec<u8>>,
                ),
                TransportError,
            > {
                Err(TransportError::Other("dummy".into()))
            }
        }
        fn assert_send<T: Send>() {}
        assert_send::<Ssh3TransportServerShared<Dummy>>();
    }

    #[test]
    fn transport_error_roundtrip() {
        let cases = vec![
            TransportError::ChannelClosed("gone".into()),
            TransportError::OpenFailed("refused".into()),
            TransportError::Timeout,
            TransportError::Other("oops".into()),
        ];
        for err in &cases {
            let json = serde_json::to_string(err).unwrap();
            let decoded: TransportError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), decoded.to_string());
        }
    }
}
