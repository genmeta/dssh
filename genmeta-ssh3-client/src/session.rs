//! Client-side SSH3 session management.
//!
//! Provides helpers for building session channel requests (exec, shell,
//! pty-req, window-change) and decoding session responses (stdout via
//! ChannelData, stderr via ChannelExtendedData, exit-status, EOF, Close).
//!
//! The client opens a session channel via [`open_session_channel`], then uses
//! methods on [`SessionChannel`] for requests and event reading.

use std::convert::Infallible;

use genmeta_ssh::{
    AwaitOpenError, ChannelEvent, ChannelOpen, ChannelOpenFailure, DEFAULT_MAX_MESSAGE_SIZE,
    EmptyPayload, ExecChannelRequest, ExecRequest, ExitSignalRequest, ExitStatusRequest,
    PtyChannelRequest, PtyRequest, ReadChannelEventError, SshChannel,
    SendChannelNoticeError, SendChannelRequestError,
    SessionChannelOpen, ShellChannelRequest, SignalChannelNotice, SignalChannelRequest,
    SignalRequest, WindowChangeChannelNotice, WindowChangeRequest, WriteChannelCloseError,
    WriteDataError, WriteChannelEofError,
    read_channel_open_response,
};
use genmeta_ssh::session::SessionCodecError;
use h3x::codec::{EncodeExt, EncodeInto, SinkWriter, StreamReader};
use h3x::varint::VarInt;
use snafu::Snafu;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Snafu)]
pub enum ClientSessionError {
    #[snafu(display("failed to open QUIC bidirectional stream"))]
    OpenStream { source: std::io::Error },

    #[snafu(display("invalid conversation_id"))]
    InvalidConversationId { source: std::io::Error },

    #[snafu(display("failed to encode channel open max_message_size"))]
    EncodeMaxMessageSize { source: std::io::Error },

    #[snafu(display("failed to encode channel open channel_type"))]
    EncodeChannelType { source: genmeta_ssh::codec::CodecError },

    #[snafu(display("failed to flush channel open"))]
    FlushChannelOpen { source: std::io::Error },

    #[snafu(display("failed to read channel open response"))]
    AwaitOpen { source: AwaitOpenError },

    #[snafu(display("session channel was rejected"))]
    ChannelOpenRejected { failure: ChannelOpenFailure },

    #[snafu(display("failed to send exec request"))]
    SendExecRequest {
        source: SendChannelRequestError<SessionCodecError, Infallible>,
    },

    #[snafu(display("failed to send shell request"))]
    SendShellRequest {
        source: SendChannelRequestError<Infallible, Infallible>,
    },

    #[snafu(display("failed to send pty request"))]
    SendPtyRequest {
        source: SendChannelRequestError<SessionCodecError, Infallible>,
    },

    #[snafu(display("failed to send signal request"))]
    SendSignalRequest {
        source: SendChannelRequestError<SessionCodecError, Infallible>,
    },

    #[snafu(display("failed to send window change notice"))]
    SendWindowChange {
        source: SendChannelNoticeError<SessionCodecError>,
    },

    #[snafu(display("failed to send signal notice"))]
    SendSignalNotice {
        source: SendChannelNoticeError<SessionCodecError>,
    },

    #[snafu(display("failed to write channel data"))]
    WriteData { source: WriteDataError },

    #[snafu(display("failed to write channel EOF"))]
    WriteEof { source: WriteChannelEofError },

    #[snafu(display("failed to write channel close"))]
    WriteClose { source: WriteChannelCloseError },

    #[snafu(display("failed to read channel event"))]
    ReadEvent { source: ReadChannelEventError },

    #[snafu(display("failed to decode exit-status payload"))]
    DecodeExitStatus { source: SessionCodecError },

    #[snafu(display("failed to decode exit-signal payload"))]
    DecodeExitSignal { source: SessionCodecError },

    #[snafu(display("failed to read channel data"))]
    ReadData { source: std::io::Error },

    #[snafu(display("channel request was rejected by remote"))]
    RequestRejected,

    #[snafu(display("unexpected channel event while expecting success"))]
    UnexpectedEvent,

    #[snafu(display("channel closed before request reply"))]
    ChannelClosed,
}

#[derive(Debug)]
pub struct SessionChannel<R, W> {
    channel: SshChannel<R, W>,
}

pub type ClientChannelReader<R> = StreamReader<R>;
pub type ClientChannelWriter<W> = SinkWriter<W>;

impl<R, W> SessionChannel<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    pub fn reader_mut(&mut self) -> &mut R {
        self.channel.reader_mut()
    }

    pub fn writer_mut(&mut self) -> &mut W {
        self.channel.writer_mut()
    }

    pub async fn send_exec_request(
        &mut self,
        command: &[u8],
    ) -> Result<(), ClientSessionError> {
        let req = ExecChannelRequest {
            payload: ExecRequest {
                command: command.to_vec().into(),
            },
        };
        self.channel
            .request(&req)
            .await
            .map(|_: EmptyPayload| ())
            .map_err(|e| match e {
                SendChannelRequestError::Rejected => ClientSessionError::RequestRejected,
                other => ClientSessionError::SendExecRequest { source: other },
            })
    }

    pub async fn send_shell_request(&mut self) -> Result<(), ClientSessionError> {
        let req = ShellChannelRequest;
        self.channel
            .request(&req)
            .await
            .map(|_: EmptyPayload| ())
            .map_err(|e| match e {
                SendChannelRequestError::Rejected => ClientSessionError::RequestRejected,
                other => ClientSessionError::SendShellRequest { source: other },
            })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_pty_request(
        &mut self,
        term: &str,
        width_cols: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
        terminal_modes: &[u8],
    ) -> Result<(), ClientSessionError> {
        let req = PtyChannelRequest {
            payload: PtyRequest {
                term_type: term.to_owned().into(),
                width_cols: width_cols.into(),
                height_rows: height_rows.into(),
                width_px: width_px.into(),
                height_px: height_px.into(),
                terminal_modes: terminal_modes.to_vec().into(),
            },
        };
        self.channel
            .request(&req)
            .await
            .map(|_: EmptyPayload| ())
            .map_err(|e| match e {
                SendChannelRequestError::Rejected => ClientSessionError::RequestRejected,
                other => ClientSessionError::SendPtyRequest { source: other },
            })
    }

    pub async fn send_window_change(
        &mut self,
        width_cols: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
    ) -> Result<(), ClientSessionError> {
        let req = WindowChangeChannelNotice {
            payload: WindowChangeRequest {
                width_cols: width_cols.into(),
                height_rows: height_rows.into(),
                width_px: width_px.into(),
                height_px: height_px.into(),
            },
        };
        self.channel
            .notice(&req)
            .await
            .map_err(|e| ClientSessionError::SendWindowChange { source: e })
    }

    pub async fn send_signal(
        &mut self,
        signal_name: &str,
        want_reply: bool,
    ) -> Result<(), ClientSessionError> {
        if want_reply {
            let req = SignalChannelRequest {
                payload: SignalRequest {
                    signal_name: signal_name.to_owned().into(),
                },
            };
            self.channel
                .request(&req)
                .await
                .map(|_: EmptyPayload| ())
                .map_err(|e| match e {
                    SendChannelRequestError::Rejected => ClientSessionError::RequestRejected,
                    other => ClientSessionError::SendSignalRequest { source: other },
                })
        } else {
            let req = SignalChannelNotice {
                payload: SignalRequest {
                    signal_name: signal_name.to_owned().into(),
                },
            };
            self.channel
                .notice(&req)
                .await
                .map_err(|e| ClientSessionError::SendSignalNotice { source: e })
        }
    }

    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<(), ClientSessionError> {
        self.channel
            .data(data)
            .await
            .map_err(|e| ClientSessionError::WriteData { source: e })
    }

    pub async fn send_eof(&mut self) -> Result<(), ClientSessionError> {
        self.channel
            .eof()
            .await
            .map_err(|e| ClientSessionError::WriteEof { source: e })
    }

    pub async fn send_close(&mut self) -> Result<(), ClientSessionError> {
        self.channel
            .close()
            .await
            .map_err(|e| ClientSessionError::WriteClose { source: e })
    }

    /// Read the next session event from the channel.
    ///
    /// Returns `None` on EOF (stream closed).
    pub async fn recv_event(&mut self) -> Result<Option<SessionEvent>, ClientSessionError> {
        loop {
            let event = match self.channel.next_event().await {
                Ok(event) => event,
                Err(ReadChannelEventError::DecodeMessageType { source })
                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(ClientSessionError::ReadEvent { source: e }),
            };
            if let Some(session_event) = channel_event_to_session_event(event).await? {
                return Ok(Some(session_event));
            }
        }
    }

    pub fn into_parts(self) -> (R, W) {
        self.channel.into_parts()
    }
}

/// Open a session channel on the given stream pair.
///
/// Writes the channel open header (max_message_size, channel_type, payload)
/// and reads the confirmation/failure response.
pub async fn open_session_channel<R, W>(
    mut reader: R,
    mut writer: W,
    _conversation_id: u64,
) -> Result<SessionChannel<R, W>, ClientSessionError>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let open = SessionChannelOpen;

    // Encode channel open: max_message_size, channel_type, payload
    writer
        .encode_one(DEFAULT_MAX_MESSAGE_SIZE)
        .await
        .map_err(|e| ClientSessionError::EncodeMaxMessageSize { source: e })?;
    writer
        .encode_one(open.channel_type())
        .await
        .map_err(|e| ClientSessionError::EncodeChannelType { source: e })?;
    // SessionChannelOpen has no payload fields, but encode it for consistency
    open.payload()
        .clone()
        .encode_into(&mut writer)
        .await
        .map_err(|e: Infallible| match e {})?;
    writer
        .flush()
        .await
        .map_err(|e| ClientSessionError::FlushChannelOpen { source: e })?;

    // Read confirmation or failure
    match read_channel_open_response(&mut reader).await {
        Ok(()) => Ok(SessionChannel {
            channel: SshChannel::new(reader, writer),
        }),
        Err(AwaitOpenError::Rejected { failure }) => {
            Err(ClientSessionError::ChannelOpenRejected { failure })
        }
        Err(source) => Err(ClientSessionError::AwaitOpen { source }),
    }
}

// ---------------------------------------------------------------------------
// Response parsing helpers
// ---------------------------------------------------------------------------

/// Parsed session output — a single message received from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// Stdout data received via ChannelData(94).
    Stdout(Vec<u8>),
    /// Stderr data received via ChannelExtendedData(95) with data_type=1.
    Stderr(Vec<u8>),
    /// The server reported the process exit code.
    ExitStatus(u32),
    /// The server reported the process was killed by a signal (RFC 4254 §6.10).
    ExitSignal {
        /// Signal name without `SIG` prefix (e.g., `TERM`, `KILL`).
        name: String,
        /// Whether a core dump was produced.
        core_dumped: bool,
        /// Error message (may be empty).
        message: String,
        /// Language tag for the error message (may be empty).
        language: String,
    },
    /// The server signaled end-of-file.
    Eof,
    /// The server closed the channel.
    Close,
    /// ChannelSuccess — reply to a want_reply=true request.
    Success,
    /// ChannelFailure — reply to a want_reply=true request.
    Failure,
}

/// Convert a [`ChannelEvent`] into a [`SessionEvent`].
///
/// Returns `None` for events not relevant to session handling (e.g., unknown
/// channel request types).
async fn channel_event_to_session_event<'c, R, W>(
    event: ChannelEvent<'c, R, W>,
) -> Result<Option<SessionEvent>, ClientSessionError>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    match event {
        ChannelEvent::Data(mut data) => {
            let bytes = data
                .read_all()
                .await
                .map_err(|e| ClientSessionError::ReadData { source: e })?;
            Ok(Some(SessionEvent::Stdout(bytes)))
        }
        ChannelEvent::ExtendedData { data_type, mut data } => {
            let bytes = data
                .read_all()
                .await
                .map_err(|e| ClientSessionError::ReadData { source: e })?;
            if data_type == VarInt::from(1u8) {
                Ok(Some(SessionEvent::Stderr(bytes)))
            } else {
                tracing::warn!(%data_type, "ignoring unknown extended data type");
                Ok(None)
            }
        }
        ChannelEvent::Request(req) => {
            let request_type = req.request_type().clone();
            match &*request_type {
                "exit-status" => {
                    let (payload, _responder): (ExitStatusRequest, _) = req
                        .decode_payload()
                        .await
                        .map_err(|e| ClientSessionError::DecodeExitStatus { source: e })?;
                    Ok(Some(SessionEvent::ExitStatus(
                        payload.exit_status.into_inner() as u32,
                    )))
                }
                "exit-signal" => {
                    let (payload, _responder): (ExitSignalRequest, _) = req
                        .decode_payload()
                        .await
                        .map_err(|e| ClientSessionError::DecodeExitSignal { source: e })?;
                    Ok(Some(SessionEvent::ExitSignal {
                        name: payload.signal_name.to_string(),
                        core_dumped: payload.core_dumped.0,
                        message: payload.error_message.to_string(),
                        language: payload.language_tag.to_string(),
                    }))
                }
                _ => {
                    // Unknown request type — skip remaining payload.
                    // Note: the stream may be in an inconsistent state after this,
                    // but for a client reading session events this is acceptable
                    // since we don't control what the server sends.
                    tracing::warn!(
                        request_type = %&*request_type,
                        "ignoring unknown channel request type"
                    );
                    Ok(None)
                }
            }
        }
        ChannelEvent::Success => Ok(Some(SessionEvent::Success)),
        ChannelEvent::Failure => Ok(Some(SessionEvent::Failure)),
        ChannelEvent::Eof => Ok(Some(SessionEvent::Eof)),
        ChannelEvent::Close => Ok(Some(SessionEvent::Close)),
    }
}

/// Read a single session event from a `SshChannel`.
///
/// Returns `None` on EOF.
pub async fn read_session_event<R, W>(
    channel: &mut SshChannel<R, W>,
) -> Result<Option<SessionEvent>, ClientSessionError>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    loop {
        let event = match channel.next_event().await {
            Ok(event) => event,
            Err(ReadChannelEventError::DecodeMessageType { source })
                if source.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(None);
            }
            Err(e) => return Err(ClientSessionError::ReadEvent { source: e }),
        };
        if let Some(session_event) = channel_event_to_session_event(event).await? {
            return Ok(Some(session_event));
        }
    }
}

/// Legacy compatibility helper: convert a `SessionEvent::ExitSignal` into an
/// `ExitStatus(128 + signal_number)` using standard POSIX signal numbering.
///
/// Returns the original event unchanged for non-signal events.
/// Unrecognized signal names map to `ExitStatus(255)`.
pub fn exit_signal_to_legacy_status(event: SessionEvent) -> SessionEvent {
    match event {
        SessionEvent::ExitSignal { ref name, .. } => {
            let sig_num: u32 = match name.as_str() {
                "HUP" => 1,
                "INT" => 2,
                "QUIT" => 3,
                "ILL" => 4,
                "TRAP" => 5,
                "ABRT" | "IOT" => 6,
                "BUS" => 7,
                "FPE" => 8,
                "KILL" => 9,
                "USR1" => 10,
                "SEGV" => 11,
                "USR2" => 12,
                "PIPE" => 13,
                "ALRM" => 14,
                "TERM" => 15,
                _ => return SessionEvent::ExitStatus(255),
            };
            SessionEvent::ExitStatus(128 + sig_num)
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh::{
        ChannelHeader, ChannelMessage, ChannelOpenBody,
        ChannelRequest as SshChannelRequest,
        ExecRequest, ExitSignalRequest, ExitStatusRequest,
        PtyRequest, SshMessage, WindowChangeRequest,
        encode_exit_status,
    };
    use genmeta_ssh::codec::{SshBool, SshBytes};
    use h3x::codec::{DecodeFrom, EncodeExt, EncodeInto};
    use tokio::io::{AsyncReadExt, duplex};

    async fn encode_request_data<T, E>(item: T) -> Result<Vec<u8>, E>
    where
        for<'a> T: EncodeInto<&'a mut Vec<u8>, Output = (), Error = E>,
    {
        let mut buf = Vec::new();
        buf.encode_one(item).await?;
        Ok(buf)
    }

    // -------------------------------------------------------------------
    // Test 1: exec request encoding verified against server's parser
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_data_roundtrip() {
        let data = encode_request_data(ExecRequest {
            command: SshBytes::from(b"echo hello".to_vec()),
        })
        .await
        .unwrap();
        let req = ExecRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.command.as_ref(), &b"echo hello"[..]);
    }

    #[tokio::test]
    async fn open_session_channel_writes_header_and_accepts_confirmation() {
        let (client_reader, mut server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let server = tokio::spawn(async move {
            let header = ChannelHeader::decode_from(&mut server_reader)
                .await
                .unwrap();
            assert!(matches!(header.body, ChannelOpenBody::Session));
            SshMessage::Channel(ChannelMessage::OpenConfirmation {
                max_message_size: VarInt::from(4096u32),
            })
            .encode_into(&mut server_writer)
            .await
            .unwrap();
        });

        let channel = open_session_channel(client_reader, client_writer, 77)
            .await
            .unwrap();
        assert_eq!(channel.max_message_size(), VarInt::from(4096u32));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn open_session_channel_reports_open_failure() {
        let (client_reader, mut server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let server = tokio::spawn(async move {
            let _header = ChannelHeader::decode_from(&mut server_reader)
                .await
                .unwrap();
            SshMessage::Channel(ChannelMessage::OpenFailure(ChannelOpenFailure {
                reason_code: VarInt::from(3u8),
                description: "denied".into(),
            }))
            .encode_into(&mut server_writer)
            .await
            .unwrap();
        });

        let err = open_session_channel(client_reader, client_writer, 1)
            .await
            .unwrap_err();
        match err {
            ClientSessionError::ChannelOpenRejected { failure } => {
                assert_eq!(failure.reason_code, VarInt::from(3u8));
                assert_eq!(&*failure.description, "denied");
            }
            other => panic!("expected ChannelOpenRejected, got {other:?}"),
        }

        server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 2: exec request hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_data_hex_dump() {
        let data = encode_request_data(ExecRequest {
            command: SshBytes::from(b"hi".to_vec()),
        })
        .await
        .unwrap();
        // "hi": varint(2)=0x02, b"hi"=[0x68, 0x69]
        assert_eq!(data, vec![0x02, 0x68, 0x69]);
    }

    // -------------------------------------------------------------------
    // Test 3: send_exec_request produces correct ChannelRequest(98)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_remote_command() {
        let (client_reader, mut server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let server = tokio::spawn(async move {
            let msg = SshMessage::decode_from(&mut server_reader).await.unwrap();
            match msg {
                SshMessage::Channel(ChannelMessage::Request(
                    SshChannelRequest::Exec { want_reply, request },
                )) => {
                    assert!(want_reply.0);
                    assert_eq!(request.command.as_ref(), &b"echo hello"[..]);
                }
                other => panic!("expected exec ChannelRequest, got {other:?}"),
            }
            SshMessage::Channel(ChannelMessage::Success)
                .encode_into(&mut server_writer)
                .await
                .unwrap();
        });

        let mut channel = SessionChannel {
            reader: client_reader,
            writer: client_writer,
            max_message_size: VarInt::from(1024u32),
        };
        channel.send_exec_request(b"echo hello").await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exec_request_data_allows_non_utf8_bytes() {
        let data = encode_request_data(ExecRequest {
            command: SshBytes::from(vec![0x66, 0x6f, 0xff]),
        })
        .await
        .unwrap();

        let mut reader = data.as_slice();
        let len = VarInt::decode_from(&mut reader).await.unwrap();
        assert_eq!(len.into_inner(), 3);

        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, vec![0x66, 0x6f, 0xff]);
    }

    // -------------------------------------------------------------------
    // Test 4: shell request
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn shell_request() {
        let (client_reader, mut server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let server = tokio::spawn(async move {
            let msg = SshMessage::decode_from(&mut server_reader).await.unwrap();
            match msg {
                SshMessage::Channel(ChannelMessage::Request(
                    SshChannelRequest::Shell { want_reply },
                )) => {
                    assert!(want_reply.0);
                }
                other => panic!("expected shell ChannelRequest, got {other:?}"),
            }
            SshMessage::Channel(ChannelMessage::Success)
                .encode_into(&mut server_writer)
                .await
                .unwrap();
        });

        let mut channel = SessionChannel {
            reader: client_reader,
            writer: client_writer,
            max_message_size: VarInt::from(1024u32),
        };
        channel.send_shell_request().await.unwrap();
        server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 5: pty-req request roundtrip with server parser
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pty_request_roundtrip() {
        let data = encode_request_data(PtyRequest {
            term_type: "xterm-256color".into(),
            width_cols: 80u32.into(),
            height_rows: 24u32.into(),
            width_px: 640u32.into(),
            height_px: 480u32.into(),
            terminal_modes: SshBytes::from(vec![0x01, 0x00, 0x00, 0x00, 0x03]),
        })
        .await
        .unwrap();

        // Parse with server's parser
        let parsed = PtyRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(&*parsed.term_type, "xterm-256color");
        assert_eq!(parsed.width_cols, VarInt::from(80u32));
        assert_eq!(parsed.height_rows, VarInt::from(24u32));
        assert_eq!(parsed.width_px, VarInt::from(640u32));
        assert_eq!(parsed.height_px, VarInt::from(480u32));
        assert_eq!(parsed.terminal_modes.as_ref(), &[0x01u8, 0x00, 0x00, 0x00, 0x03][..]);
    }

    // -------------------------------------------------------------------
    // Test 6: window-change request roundtrip with server parser
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn window_change_roundtrip() {
        let data = encode_request_data(WindowChangeRequest {
            width_cols: 120u32.into(),
            height_rows: 40u32.into(),
            width_px: 960u32.into(),
            height_px: 800u32.into(),
        })
        .await
        .unwrap();

        let parsed = WindowChangeRequest::decode_from(data.as_slice())
            .await
            .unwrap();
        assert_eq!(parsed.width_cols, VarInt::from(120u32));
        assert_eq!(parsed.height_rows, VarInt::from(40u32));
        assert_eq!(parsed.width_px, VarInt::from(960u32));
        assert_eq!(parsed.height_px, VarInt::from(800u32));
    }

    // -------------------------------------------------------------------
    // Test 7: ChannelData → SessionEvent::Stdout
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn channel_data_to_stdout() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Data(SshBytes::from(b"hello\n".to_vec())))
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(event, Some(SessionEvent::Stdout(b"hello\n".to_vec())));
    }

    // -------------------------------------------------------------------
    // Test 8: ChannelExtendedData(type=1) → SessionEvent::Stderr
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn stderr_via_extended_data() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::ExtendedData {
            data_type: VarInt::from(1u8),
            data: SshBytes::from(b"error output".to_vec()),
        })
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);
        let event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(event, Some(SessionEvent::Stderr(b"error output".to_vec())));
    }

    // -------------------------------------------------------------------
    // Test 9: exit-status extraction
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_extraction() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Request(SshChannelRequest::ExitStatus(
            ExitStatusRequest {
                exit_status: VarInt::from(42u32),
            },
        )))
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);
        let event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(event, Some(SessionEvent::ExitStatus(42)));
    }

    // -------------------------------------------------------------------
    // Test 10: exit-status zero
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_zero() {
        let request_data = encode_request_data(ExitStatusRequest {
            exit_status: VarInt::from(0u32),
        })
        .await
        .unwrap();
        let code = ExitStatusRequest::decode_from(request_data.as_slice())
            .await
            .unwrap()
            .exit_status;
        assert_eq!(code, VarInt::from(0u32));
    }

    // -------------------------------------------------------------------
    // Test 11: exit-status 255
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_255() {
        let request_data = encode_request_data(ExitStatusRequest {
            exit_status: VarInt::from(255u32),
        })
        .await
        .unwrap();
        let code = ExitStatusRequest::decode_from(request_data.as_slice())
            .await
            .unwrap()
            .exit_status;
        assert_eq!(code, VarInt::from(255u32));
    }

    // -------------------------------------------------------------------
    // Test 12: exit-status hex dump verification
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_hex_dump() {
        // exit code 0 → varint 0x00
        let data0 = encode_exit_status(0);
        assert_eq!(data0, vec![0x00]);

        // exit code 1 → varint 0x01
        let data1 = encode_exit_status(1);
        assert_eq!(data1, vec![0x01]);

        // exit code 127 → 2-byte varint [0x40, 0x7f]
        let data127 = encode_exit_status(127);
        assert_eq!(data127, vec![0x40, 0x7f]);
    }

    // -------------------------------------------------------------------
    // Test 13: EOF and Close events
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn eof_and_close_events() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Eof)
            .encode_into(&mut writer)
            .await
            .unwrap();
        SshMessage::Channel(ChannelMessage::Close)
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let eof_event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(eof_event, Some(SessionEvent::Eof));

        let close_event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(close_event, Some(SessionEvent::Close));
    }

    // -------------------------------------------------------------------
    // Test 14: Success and Failure events
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn success_and_failure_events() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Success)
            .encode_into(&mut writer)
            .await
            .unwrap();
        SshMessage::Channel(ChannelMessage::Failure)
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let success = read_session_event(&mut reader).await.unwrap();
        assert_eq!(success, Some(SessionEvent::Success));

        let failure = read_session_event(&mut reader).await.unwrap();
        assert_eq!(failure, Some(SessionEvent::Failure));
    }

    // -------------------------------------------------------------------
    // Test 15: full exec lifecycle simulation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn full_exec_lifecycle() {
        // Simulate server-side responses for "echo hello":
        // 1. ChannelSuccess (reply to exec)
        // 2. ChannelData("hello\n")
        // 3. exit-status(0)
        // 4. ChannelEof
        // 5. ChannelClose
        let (mut server_writer, mut client_reader) = duplex(8192);

        // Server writes responses
        let server_task = tokio::spawn(async move {
            SshMessage::Channel(ChannelMessage::Success)
                .encode_into(&mut server_writer)
                .await
                .unwrap();
            SshMessage::Channel(ChannelMessage::Data(SshBytes::from(
                b"hello\n".to_vec(),
            )))
            .encode_into(&mut server_writer)
            .await
            .unwrap();

            SshMessage::Channel(ChannelMessage::Request(SshChannelRequest::ExitStatus(
                ExitStatusRequest {
                    exit_status: VarInt::from(0u32),
                },
            )))
            .encode_into(&mut server_writer)
            .await
            .unwrap();

            SshMessage::Channel(ChannelMessage::Eof)
                .encode_into(&mut server_writer)
                .await
                .unwrap();
            SshMessage::Channel(ChannelMessage::Close)
                .encode_into(&mut server_writer)
                .await
                .unwrap();

            drop(server_writer);
        });

        // Client reads and converts to SessionEvents
        let mut events = Vec::new();
        loop {
            match read_session_event(&mut client_reader).await {
                Ok(Some(event)) => events.push(event),
                Ok(None) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        server_task.await.unwrap();

        assert_eq!(
            events,
            vec![
                SessionEvent::Success,
                SessionEvent::Stdout(b"hello\n".to_vec()),
                SessionEvent::ExitStatus(0),
                SessionEvent::Eof,
                SessionEvent::Close,
            ]
        );
    }

    // -------------------------------------------------------------------
    // Test 16: send_pty_request produces correct wire format
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_pty_request_wire_format() {
        let (client_reader, mut server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let server = tokio::spawn(async move {
            let msg = SshMessage::decode_from(&mut server_reader).await.unwrap();
            match msg {
                SshMessage::Channel(ChannelMessage::Request(
                    SshChannelRequest::PtyReq { want_reply, request },
                )) => {
                    assert!(want_reply.0);
                    assert_eq!(&*request.term_type, "xterm");
                    assert_eq!(request.width_cols, VarInt::from(80u32));
                    assert_eq!(request.height_rows, VarInt::from(24u32));
                }
                other => panic!("expected pty-req ChannelRequest, got {other:?}"),
            }
            SshMessage::Channel(ChannelMessage::Success)
                .encode_into(&mut server_writer)
                .await
                .unwrap();
        });

        let mut channel = SessionChannel {
            reader: client_reader,
            writer: client_writer,
            max_message_size: VarInt::from(1024u32),
        };
        channel
            .send_pty_request("xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 17: send_window_change wire format
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_window_change_wire_format() {
        let (client_reader, _server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let mut channel = SessionChannel {
            reader: client_reader,
            writer: client_writer,
            max_message_size: VarInt::from(1024u32),
        };
        channel
            .send_window_change(120, 40, 960, 800)
            .await
            .unwrap();
        drop(channel);

        let msg = SshMessage::decode_from(&mut server_reader).await.unwrap();
        match msg {
            SshMessage::Channel(ChannelMessage::Request(
                SshChannelRequest::WindowChange(request),
            )) => {
                assert_eq!(request.width_cols, VarInt::from(120u32));
                assert_eq!(request.height_rows, VarInt::from(40u32));
                assert_eq!(request.width_px, VarInt::from(960u32));
                assert_eq!(request.height_px, VarInt::from(800u32));
            }
            other => panic!("expected window-change ChannelRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_signal_request_wire_format() {
        let (client_reader, _server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let mut channel = SessionChannel {
            reader: client_reader,
            writer: client_writer,
            max_message_size: VarInt::from(1024u32),
        };
        channel.send_signal("TERM", false).await.unwrap();
        drop(channel);

        let msg = SshMessage::decode_from(&mut server_reader).await.unwrap();
        match msg {
            SshMessage::Channel(ChannelMessage::Request(
                SshChannelRequest::Signal { want_reply, request },
            )) => {
                assert!(!want_reply.0);
                assert_eq!(&*request.signal_name, "TERM");
            }
            other => panic!("expected signal ChannelRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_channel_send_stdin_and_eof() {
        let (channel_reader, _channel_writer) = duplex(8192);
        let (mut peer_reader, peer_writer) = duplex(8192);
        let mut channel = SessionChannel {
            reader: channel_reader,
            writer: peer_writer,
            max_message_size: VarInt::from(1024u32),
        };

        channel.send_stdin(b"hello").await.unwrap();
        channel.send_eof().await.unwrap();
        drop(channel);

        let data = SshMessage::decode_from(&mut peer_reader).await.unwrap();
        match data {
            SshMessage::Channel(ChannelMessage::Data(bytes)) => {
                assert_eq!(bytes.as_ref(), &b"hello"[..]);
            }
            other => panic!("expected channel data, got {other:?}"),
        }
        let eof = SshMessage::decode_from(&mut peer_reader).await.unwrap();
        assert!(matches!(eof, SshMessage::Channel(ChannelMessage::Eof)));
    }

    #[tokio::test]
    async fn session_channel_recv_event_returns_success() {
        let (mut server_writer, client_reader) = duplex(8192);
        let (other_reader, other_writer) = duplex(8192);
        let mut channel = SessionChannel {
            reader: client_reader,
            writer: other_writer,
            max_message_size: VarInt::from(1024u32),
        };

        SshMessage::Channel(ChannelMessage::Success)
            .encode_into(&mut server_writer)
            .await
            .unwrap();
        drop(server_writer);

        let event = channel.recv_event().await.unwrap();
        assert_eq!(event, Some(SessionEvent::Success));
        drop(other_reader);
    }

    // -------------------------------------------------------------------
    // Test 18: stderr separated from stdout
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn stderr_separated_from_stdout() {
        let (mut server_writer, mut client_reader) = duplex(8192);

        // Server sends stdout then stderr
        SshMessage::Channel(ChannelMessage::Data(SshBytes::from(
            b"stdout data".to_vec(),
        )))
        .encode_into(&mut server_writer)
        .await
        .unwrap();
        SshMessage::Channel(ChannelMessage::ExtendedData {
            data_type: VarInt::from(1u8),
            data: SshBytes::from(b"stderr data".to_vec()),
        })
        .encode_into(&mut server_writer)
        .await
        .unwrap();
        drop(server_writer);

        // Read messages and separate stdout/stderr
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        loop {
            match read_session_event(&mut client_reader).await {
                Ok(Some(event)) => match event {
                    SessionEvent::Stdout(data) => stdout.extend(data),
                    SessionEvent::Stderr(data) => stderr.extend(data),
                    _ => {}
                },
                Ok(None) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert_eq!(stdout, b"stdout data");
        assert_eq!(stderr, b"stderr data");
    }

    // -------------------------------------------------------------------
    // Test 19: exit-signal decodes to SessionEvent::ExitSignal
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_signal_decodes_to_exit_signal_event() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Request(SshChannelRequest::ExitSignal(
            ExitSignalRequest {
                signal_name: "TERM".into(),
                core_dumped: SshBool(false),
                error_message: "terminated".into(),
                language_tag: "en".into(),
            },
        )))
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);
        let event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(
            event,
            Some(SessionEvent::ExitSignal {
                name: "TERM".into(),
                core_dumped: false,
                message: "terminated".into(),
                language: "en".into(),
            })
        );
    }

    #[tokio::test]
    async fn exit_signal_with_core_dump() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Request(SshChannelRequest::ExitSignal(
            ExitSignalRequest {
                signal_name: "SEGV".into(),
                core_dumped: SshBool(true),
                error_message: "segfault".into(),
                language_tag: "".into(),
            },
        )))
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);
        let event = read_session_event(&mut reader).await.unwrap();
        assert_eq!(
            event,
            Some(SessionEvent::ExitSignal {
                name: "SEGV".into(),
                core_dumped: true,
                message: "segfault".into(),
                language: String::new(),
            })
        );
    }

    // -------------------------------------------------------------------
    // Test 20: exit-status still decodes correctly (not regressed)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_still_decodes_correctly() {
        for code in [0u32, 1, 42, 127, 255] {
            let (mut writer, mut reader) = duplex(8192);
            SshMessage::Channel(ChannelMessage::Request(SshChannelRequest::ExitStatus(
                ExitStatusRequest {
                    exit_status: VarInt::from(code),
                },
            )))
            .encode_into(&mut writer)
            .await
            .unwrap();
            drop(writer);
            let event = read_session_event(&mut reader).await.unwrap();
            assert_eq!(event, Some(SessionEvent::ExitStatus(code)));
        }
    }

    // -------------------------------------------------------------------
    // Test 21: compatibility helper maps signal to legacy status
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compat_helper_maps_known_signals() {
        let cases = [
            ("HUP", 128 + 1),
            ("INT", 128 + 2),
            ("QUIT", 128 + 3),
            ("ILL", 128 + 4),
            ("TRAP", 128 + 5),
            ("ABRT", 128 + 6),
            ("BUS", 128 + 7),
            ("FPE", 128 + 8),
            ("KILL", 128 + 9),
            ("USR1", 128 + 10),
            ("SEGV", 128 + 11),
            ("USR2", 128 + 12),
            ("PIPE", 128 + 13),
            ("ALRM", 128 + 14),
            ("TERM", 128 + 15),
        ];
        for (sig, expected_code) in cases {
            let event = SessionEvent::ExitSignal {
                name: sig.into(),
                core_dumped: false,
                message: String::new(),
                language: String::new(),
            };
            assert_eq!(
                exit_signal_to_legacy_status(event),
                SessionEvent::ExitStatus(expected_code),
                "signal {sig} should map to exit code {expected_code}"
            );
        }
    }

    #[tokio::test]
    async fn compat_helper_unknown_signal_maps_to_255() {
        let event = SessionEvent::ExitSignal {
            name: "UNKNOWN".into(),
            core_dumped: false,
            message: String::new(),
            language: String::new(),
        };
        assert_eq!(
            exit_signal_to_legacy_status(event),
            SessionEvent::ExitStatus(255)
        );
    }

    #[tokio::test]
    async fn compat_helper_passes_through_non_signal_events() {
        let events = vec![
            SessionEvent::ExitStatus(42),
            SessionEvent::Stdout(b"data".to_vec()),
            SessionEvent::Eof,
            SessionEvent::Close,
        ];
        for event in events {
            let original = event.clone();
            assert_eq!(exit_signal_to_legacy_status(event), original);
        }
    }
}
