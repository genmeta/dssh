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
    codec::{SshBool, SshString, checked_remote_field_len},
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    message::SshMessage,
};
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tracing::Instrument;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    Exec(Vec<u8>),
    Shell,
    AllocatePty(PtyRequest, bool),
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
    event: &ChannelEvent,
    writer: &mut W,
) -> io::Result<Option<RequestAction>>
where
    W: AsyncWrite + Send + Unpin,
{
    let (request_type, want_reply, request_data) = match event {
        ChannelEvent::Request {
            request_type,
            want_reply,
            request_data,
        } => (request_type.as_str(), *want_reply, request_data.as_slice()),
        _ => return Ok(None),
    };

    match request_type {
        "exec" => {
            let command = request_data.decode::<ExecRequest>().await?.command;
            if want_reply {
                writer.encode_one(&SshMessage::ChannelSuccess).await?;
            }
            Ok(Some(RequestAction::Exec(command)))
        }
        "shell" => {
            if want_reply {
                writer.encode_one(&SshMessage::ChannelSuccess).await?;
            }
            Ok(Some(RequestAction::Shell))
        }
        "pty-req" => {
            let req = request_data.decode::<PtyRequest>().await?;
            Ok(Some(RequestAction::AllocatePty(req, want_reply)))
        }
        "window-change" => {
            let req = request_data.decode::<WindowChangeRequest>().await?;
            if want_reply {
                writer.encode_one(&SshMessage::ChannelSuccess).await?;
            }
            Ok(Some(RequestAction::WindowChange(req)))
        }
        "signal" => {
            let req = request_data.decode::<SignalRequest>().await?;
            if want_reply {
                writer.encode_one(&SshMessage::ChannelSuccess).await?;
            }
            Ok(Some(RequestAction::Signal(req)))
        }
        "subsystem" => {
            let _req = request_data.decode::<SubsystemRequest>().await?;
            if want_reply {
                writer.encode_one(&SshMessage::ChannelFailure).await?;
            }
            Ok(None)
        }
        "exit-status" => {
            let _req = request_data.decode::<ExitStatusRequest>().await?;
            Ok(None)
        }
        "exit-signal" => {
            let _req = request_data.decode::<ExitSignalRequest>().await?;
            Ok(None)
        }
        _ => {
            if want_reply {
                writer.encode_one(&SshMessage::ChannelFailure).await?;
            }
            Ok(None)
        }
    }
}

pub async fn handle_session_loop_event<W>(
    event: ChannelEvent,
    writer: &mut W,
) -> io::Result<SessionLoopAction>
where
    W: AsyncWrite + Send + Unpin,
{
    match event {
        ChannelEvent::Request { .. } => Ok(match handle_request(&event, writer).await? {
            Some(action) => SessionLoopAction::Request(action),
            None => SessionLoopAction::Ignore,
        }),
        ChannelEvent::Eof => {
            writer.encode_one(&SshMessage::ChannelEof).await?;
            writer.shutdown().await?;
            Ok(SessionLoopAction::Eof)
        }
        ChannelEvent::Close => {
            writer.encode_one(&SshMessage::ChannelClose).await?;
            Ok(SessionLoopAction::Close)
        }
        ChannelEvent::Data(_) | ChannelEvent::ExtendedData { .. } => Ok(SessionLoopAction::Ignore),
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
    pub command: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemRequest {
    pub subsystem_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatusRequest {
    pub exit_status: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignalRequest {
    pub signal_name: String,
    pub core_dumped: bool,
    pub error_message: String,
    pub language_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    pub term_type: String,
    pub width_cols: VarInt,
    pub height_rows: VarInt,
    pub width_px: VarInt,
    pub height_px: VarInt,
    pub terminal_modes: Vec<u8>,
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
    pub signal_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEvent {
    Data(Vec<u8>),
    ExtendedData {
        data_type: VarInt,
        data: Vec<u8>,
    },
    Request {
        request_type: String,
        want_reply: bool,
        request_data: Vec<u8>,
    },
    Eof,
    Close,
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExecRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let len: VarInt = stream.decode_one().await?;
        let len = checked_remote_field_len(len.into_inner(), "exec command")?;
        let mut command = vec![0u8; len];
        stream.read_exact(&mut command).await?;
        Ok(Self { command })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ExecRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        let len = VarInt::try_from(self.command.len() as u64)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        stream.encode_one(len).await?;
        stream.write_all(&self.command).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SubsystemRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let subsystem_name: SshString = stream.decode_one().await?;
        Ok(Self {
            subsystem_name: subsystem_name.to_string(),
        })
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitStatusRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let exit_status: VarInt = stream.decode_one().await?;
        Ok(Self { exit_status })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ExitStatusRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.exit_status).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitSignalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let signal_name: SshString = stream.decode_one().await?;
        let core_dumped: SshBool = stream.decode_one().await?;
        let error_message: SshString = stream.decode_one().await?;
        let language_tag: SshString = stream.decode_one().await?;
        Ok(Self {
            signal_name: signal_name.to_string(),
            core_dumped: core_dumped.0,
            error_message: error_message.to_string(),
            language_tag: language_tag.to_string(),
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ExitSignalRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(SshString::from(self.signal_name.clone()))
            .await?;
        stream.encode_one(SshBool(self.core_dumped)).await?;
        stream
            .encode_one(SshString::from(self.error_message.clone()))
            .await?;
        stream
            .encode_one(SshString::from(self.language_tag.clone()))
            .await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for PtyRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let term_type: SshString = stream.decode_one().await?;
        let width_cols: VarInt = stream.decode_one().await?;
        let height_rows: VarInt = stream.decode_one().await?;
        let width_px: VarInt = stream.decode_one().await?;
        let height_px: VarInt = stream.decode_one().await?;
        let modes_len: VarInt = stream.decode_one().await?;
        let modes_len = checked_remote_field_len(modes_len.into_inner(), "pty terminal modes")?;
        let mut terminal_modes = vec![0u8; modes_len];
        stream.read_exact(&mut terminal_modes).await?;
        Ok(Self {
            term_type: term_type.to_string(),
            width_cols,
            height_rows,
            width_px,
            height_px,
            terminal_modes,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &PtyRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(SshString::from(self.term_type.clone()))
            .await?;
        stream.encode_one(self.width_cols).await?;
        stream.encode_one(self.height_rows).await?;
        stream.encode_one(self.width_px).await?;
        stream.encode_one(self.height_px).await?;
        stream
            .encode_one(
                VarInt::try_from(self.terminal_modes.len()).map_err(|_overflow| {
                    io::Error::new(io::ErrorKind::InvalidInput, "too many terminal modes")
                })?,
            )
            .await?;
        stream.write_all(&self.terminal_modes).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for WindowChangeRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let width_cols: VarInt = stream.decode_one().await?;
        let height_rows: VarInt = stream.decode_one().await?;
        let width_px: VarInt = stream.decode_one().await?;
        let height_px: VarInt = stream.decode_one().await?;
        Ok(Self {
            width_cols,
            height_rows,
            width_px,
            height_px,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &WindowChangeRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.width_cols).await?;
        stream.encode_one(self.height_rows).await?;
        stream.encode_one(self.width_px).await?;
        stream.encode_one(self.height_px).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SignalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let signal_name: SshString = stream.decode_one().await?;
        Ok(Self {
            signal_name: signal_name.to_string(),
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &SignalRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(SshString::from(self.signal_name.clone()))
            .await?;
        Ok(())
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
) -> io::Result<(mpsc::Receiver<ChannelEvent>, W)>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    writer.encode_one(&confirm).await?;

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
    mut event_rx: mpsc::Receiver<ChannelEvent>,
    mut writer: W,
    mut state: S,
    mut allocate_pty: PtyFn,
    mut set_window_size: ResizeFn,
    mut run_exec: ExecFn,
    mut run_shell: ShellFn,
    mut on_signal: SignalFn,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
    ExecFn: for<'a> FnMut(
        Vec<u8>,
        &'a mut W,
        mpsc::Receiver<ChannelEvent>,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
    ShellFn: for<'a> FnMut(
        &'a mut W,
        mpsc::Receiver<ChannelEvent>,
        &'a mut S,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>,
    PtyFn: for<'a> FnMut(
        PtyRequest,
        bool,
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
    while let Some(event) = event_rx.recv().await {
        match handle_session_loop_event(event, &mut writer).await? {
            SessionLoopAction::Request(action) => match action {
                RequestAction::Exec(command) => {
                    run_exec(command, &mut writer, event_rx, &mut state).await?;
                    return Ok(());
                }
                RequestAction::Shell => {
                    run_shell(&mut writer, event_rx, &mut state).await?;
                    return Ok(());
                }
                RequestAction::AllocatePty(req, want_reply) => {
                    allocate_pty(req, want_reply, &mut writer, &mut state).await?;
                }
                RequestAction::WindowChange(req) => {
                    set_window_size(req, &mut state).await?;
                }
                RequestAction::Signal(req) => on_signal(req, &mut state).await?,
            },
            SessionLoopAction::Eof | SessionLoopAction::Close => break,
            SessionLoopAction::Ignore => {}
        }
    }

    Ok(())
}

pub async fn run_message_loop_with_sender<R>(
    mut reader: R,
    event_tx: mpsc::Sender<ChannelEvent>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin,
{
    loop {
        let msg = match reader.decode_one::<SshMessage>().await {
            Ok(msg) => msg,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
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
            crate::codec::ChannelHeader,
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
        header: Option<crate::codec::ChannelHeader>,
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
                    crate::codec::ChannelHeader,
                    remoc::rch::mpsc::Receiver<Vec<u8>>,
                    remoc::rch::mpsc::Sender<Vec<u8>>,
                )>,
                TransportError,
            > {
                Ok(None)
            }
            async fn open_channel(
                &self,
                _: Option<crate::codec::ChannelHeader>,
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
