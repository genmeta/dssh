//! Client-side SSH3 session management.
//!
//! Provides helpers for building session channel requests (exec, shell,
//! pty-req, window-change) and decoding session responses (stdout via
//! ChannelData, stderr via ChannelExtendedData, exit-status, EOF, Close).
//!
//! The client opens a session channel by writing a [`ChannelHeader`] with
//! `channel_type="session"` on a QUIC bidi stream, waits for
//! [`SshMessage::ChannelOpenConfirmation`], then sends one or more
//! [`SshMessage::ChannelRequest`] messages.

use genmeta_ssh::{
    CHANNEL_SIGNAL_VALUE, ChannelHeader, DEFAULT_MAX_MESSAGE_SIZE, ExecRequest, ExitSignalRequest,
    ExitStatusRequest, PtyRequest, SignalRequest, SshMessage, WindowChangeRequest,
};
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, SinkWriter, StreamReader};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use snafu::{ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Snafu)]
pub enum ClientSessionError {
    #[snafu(display("I/O failure while {operation}"))]
    Io {
        operation: &'static str,
        source: io::Error,
    },

    #[snafu(display("session channel was rejected: {description} (reason {reason_code})"))]
    ChannelOpenFailure {
        reason_code: u64,
        description: String,
    },

    #[snafu(display("unexpected session open response: {message:?}"))]
    UnexpectedOpenResponse { message: SshMessage },
}

#[derive(Debug)]
pub struct SessionChannel<R, W> {
    reader: R,
    writer: W,
    max_message_size: VarInt,
}

pub type ClientChannelReader<R> = StreamReader<R>;
pub type ClientChannelWriter<W> = SinkWriter<W>;

impl<R, W> SessionChannel<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    pub fn max_message_size(&self) -> VarInt {
        self.max_message_size
    }

    pub fn reader(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn writer(&mut self) -> &mut W {
        &mut self.writer
    }

    pub async fn send_exec_request(
        &mut self,
        command: &[u8],
        want_reply: bool,
    ) -> Result<(), ClientSessionError> {
        send_exec_request(&mut self.writer, command, want_reply).await
    }

    pub async fn send_shell_request(&mut self, want_reply: bool) -> Result<(), ClientSessionError> {
        send_shell_request(&mut self.writer, want_reply).await
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
        want_reply: bool,
    ) -> Result<(), ClientSessionError> {
        send_pty_request(
            &mut self.writer,
            term,
            width_cols,
            height_rows,
            width_px,
            height_px,
            terminal_modes,
            want_reply,
        )
        .await
    }

    pub async fn send_window_change(
        &mut self,
        width_cols: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
    ) -> Result<(), ClientSessionError> {
        send_window_change(
            &mut self.writer,
            width_cols,
            height_rows,
            width_px,
            height_px,
        )
        .await
    }

    pub async fn send_signal_request(
        &mut self,
        signal_name: &str,
        want_reply: bool,
    ) -> Result<(), ClientSessionError> {
        send_signal_request(&mut self.writer, signal_name, want_reply).await
    }

    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<(), ClientSessionError> {
        self.writer
            .encode_one(&SshMessage::ChannelData {
                data: data.to_vec(),
            })
            .await
            .context(IoSnafu {
                operation: "encoding channel stdin data",
            })
    }

    pub async fn send_eof(&mut self) -> Result<(), ClientSessionError> {
        self.writer
            .encode_one(&SshMessage::ChannelEof)
            .await
            .context(IoSnafu {
                operation: "encoding channel eof",
            })
    }

    pub async fn send_close(&mut self) -> Result<(), ClientSessionError> {
        self.writer
            .encode_one(&SshMessage::ChannelClose)
            .await
            .context(IoSnafu {
                operation: "encoding channel close",
            })
    }

    pub async fn read_message(&mut self) -> Result<Option<SshMessage>, ClientSessionError> {
        match SshMessage::decode_from(&mut self.reader).await {
            Ok(message) => Ok(Some(message)),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(source) => Err(ClientSessionError::Io {
                operation: "decoding session channel message",
                source,
            }),
        }
    }

    pub async fn recv_event(&mut self) -> Result<Option<SessionEvent>, ClientSessionError> {
        loop {
            let Some(message) = self.read_message().await? else {
                return Ok(None);
            };
            if let Some(event) = message_to_session_event(message).await? {
                return Ok(Some(event));
            }
        }
    }

    pub async fn expect_success(&mut self) -> Result<(), ClientSessionError> {
        match self.recv_event().await? {
            Some(SessionEvent::Success) => Ok(()),
            Some(SessionEvent::Failure) => Err(ClientSessionError::Io {
                operation: "waiting for channel success reply",
                source: io::Error::other("server returned ChannelFailure"),
            }),
            Some(other) => Err(ClientSessionError::Io {
                operation: "waiting for channel success reply",
                source: io::Error::other(format!(
                    "unexpected session event while waiting for success: {other:?}"
                )),
            }),
            None => Err(ClientSessionError::Io {
                operation: "waiting for channel success reply",
                source: io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "session channel closed before request reply",
                ),
            }),
        }
    }

    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

pub async fn open_session_channel<R, W>(
    mut reader: R,
    mut writer: W,
    conversation_id: u64,
) -> Result<SessionChannel<R, W>, ClientSessionError>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    writer
        .encode_one(ChannelHeader {
            signal_value: CHANNEL_SIGNAL_VALUE,
            conversation_id: StreamId::try_from(conversation_id)
                .map_err(io::Error::other)
                .context(IoSnafu {
                    operation: "converting conversation_id to StreamId",
                })?,
            channel_type: "session".into(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        })
        .await
        .context(IoSnafu {
            operation: "encoding session channel header",
        })?;
    writer.flush().await.context(IoSnafu {
        operation: "flushing session channel header",
    })?;

    match SshMessage::decode_from(&mut reader)
        .await
        .context(IoSnafu {
            operation: "decoding session channel open response",
        })? {
        SshMessage::ChannelOpenConfirmation { max_message_size } => Ok(SessionChannel {
            reader,
            writer,
            max_message_size,
        }),
        SshMessage::ChannelOpenFailure {
            reason_code,
            description,
        } => Err(ClientSessionError::ChannelOpenFailure {
            reason_code: reason_code.into_inner(),
            description,
        }),
        message => Err(ClientSessionError::UnexpectedOpenResponse { message }),
    }
}

// ---------------------------------------------------------------------------
// Sending session requests
// ---------------------------------------------------------------------------

/// Send a ChannelRequest with request_type="exec" and the given command.
pub async fn send_exec_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    command: &[u8],
    want_reply: bool,
) -> Result<(), ClientSessionError> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&ExecRequest {
            command: command.to_vec(),
        })
        .await
        .context(IoSnafu {
            operation: "encoding exec request data",
        })?;
    writer
        .encode_one(&SshMessage::ChannelRequest {
            request_type: "exec".into(),
            want_reply,
            request_data,
        })
        .await
        .context(IoSnafu {
            operation: "encoding exec channel request",
        })?;
    writer.flush().await.context(IoSnafu {
        operation: "flushing exec channel request",
    })
}

/// Send a ChannelRequest with request_type="shell" (no request_data).
pub async fn send_shell_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    want_reply: bool,
) -> Result<(), ClientSessionError> {
    writer
        .encode_one(&SshMessage::ChannelRequest {
            request_type: "shell".into(),
            want_reply,
            request_data: vec![],
        })
        .await
        .context(IoSnafu {
            operation: "encoding shell channel request",
        })?;
    writer.flush().await.context(IoSnafu {
        operation: "flushing shell channel request",
    })
}

/// Send a ChannelRequest with request_type="pty-req".
#[allow(clippy::too_many_arguments)]
pub async fn send_pty_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    term: &str,
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
    terminal_modes: &[u8],
    want_reply: bool,
) -> Result<(), ClientSessionError> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&PtyRequest {
            term_type: term.to_owned(),
            width_cols: width_cols.into(),
            height_rows: height_rows.into(),
            width_px: width_px.into(),
            height_px: height_px.into(),
            terminal_modes: terminal_modes.to_vec(),
        })
        .await
        .context(IoSnafu {
            operation: "encoding pty request data",
        })?;
    writer
        .encode_one(&SshMessage::ChannelRequest {
            request_type: "pty-req".into(),
            want_reply,
            request_data,
        })
        .await
        .context(IoSnafu {
            operation: "encoding pty channel request",
        })?;
    writer.flush().await.context(IoSnafu {
        operation: "flushing pty channel request",
    })
}

/// Send a ChannelRequest with request_type="window-change".
///
/// Per RFC 4254 §6.7, `want_reply` MUST be false.
pub async fn send_window_change<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
) -> Result<(), ClientSessionError> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&WindowChangeRequest {
            width_cols: width_cols.into(),
            height_rows: height_rows.into(),
            width_px: width_px.into(),
            height_px: height_px.into(),
        })
        .await
        .context(IoSnafu {
            operation: "encoding window-change request data",
        })?;
    writer
        .encode_one(&SshMessage::ChannelRequest {
            request_type: "window-change".into(),
            want_reply: false,
            request_data,
        })
        .await
        .context(IoSnafu {
            operation: "encoding window-change channel request",
        })?;
    writer.flush().await.context(IoSnafu {
        operation: "flushing window-change channel request",
    })
}

pub async fn send_signal_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    signal_name: &str,
    want_reply: bool,
) -> Result<(), ClientSessionError> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&SignalRequest {
            signal_name: signal_name.to_owned(),
        })
        .await
        .context(IoSnafu {
            operation: "encoding signal request data",
        })?;
    writer
        .encode_one(&SshMessage::ChannelRequest {
            request_type: "signal".into(),
            want_reply,
            request_data,
        })
        .await
        .context(IoSnafu {
            operation: "encoding signal channel request",
        })?;
    writer.flush().await.context(IoSnafu {
        operation: "flushing signal channel request",
    })
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

/// Convert a decoded `SshMessage` into a `SessionEvent`.
///
/// Returns `None` for message types not relevant to session handling
/// (e.g., GlobalRequest).
pub async fn message_to_session_event(
    msg: SshMessage,
) -> Result<Option<SessionEvent>, ClientSessionError> {
    match msg {
        SshMessage::ChannelData { data } => Ok(Some(SessionEvent::Stdout(data))),
        SshMessage::ChannelExtendedData { data_type, data } => {
            if data_type == VarInt::from(1u8) {
                Ok(Some(SessionEvent::Stderr(data)))
            } else {
                // Unknown extended data type — ignore.
                tracing::warn!(%data_type, "ignoring unknown extended data type");
                Ok(None)
            }
        }
        SshMessage::ChannelRequest {
            request_type,
            request_data,
            ..
        } => {
            if request_type == "exit-status" {
                let req: ExitStatusRequest =
                    request_data
                        .as_slice()
                        .decode_one()
                        .await
                        .context(IoSnafu {
                            operation: "decoding exit-status request data",
                        })?;
                Ok(Some(SessionEvent::ExitStatus(
                    req.exit_status.into_inner() as u32
                )))
            } else if request_type == "exit-signal" {
                let req: ExitSignalRequest =
                    request_data
                        .as_slice()
                        .decode_one()
                        .await
                        .context(IoSnafu {
                            operation: "decoding exit-signal request data",
                        })?;
                Ok(Some(SessionEvent::ExitSignal {
                    name: req.signal_name,
                    core_dumped: req.core_dumped,
                    message: req.error_message,
                    language: req.language_tag,
                }))
            } else {
                Ok(None)
            }
        }
        SshMessage::ChannelEof => Ok(Some(SessionEvent::Eof)),
        SshMessage::ChannelClose => Ok(Some(SessionEvent::Close)),
        SshMessage::ChannelSuccess => Ok(Some(SessionEvent::Success)),
        SshMessage::ChannelFailure => Ok(Some(SessionEvent::Failure)),
        _ => Ok(None),
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
    use genmeta_ssh::SshMessage;
    use genmeta_ssh::{
        CHANNEL_SIGNAL_VALUE, ExecRequest, ExitSignalRequest, ExitStatusRequest, PtyRequest,
        SignalRequest, WindowChangeRequest, encode_exit_status,
    };
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
        let data = encode_request_data(&ExecRequest {
            command: b"echo hello".to_vec(),
        })
        .await
        .unwrap();
        let req = ExecRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.command, b"echo hello");
    }

    #[tokio::test]
    async fn open_session_channel_writes_header_and_accepts_confirmation() {
        let (client_reader, mut server_writer) = duplex(8192);
        let (mut server_reader, client_writer) = duplex(8192);

        let server = tokio::spawn(async move {
            let header = ChannelHeader::decode_from(&mut server_reader)
                .await
                .unwrap();
            assert_eq!(header.signal_value, CHANNEL_SIGNAL_VALUE);
            assert_eq!(header.conversation_id, 77);
            assert_eq!(header.channel_type, "session");
            SshMessage::ChannelOpenConfirmation {
                max_message_size: VarInt::from(4096u32),
            }
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
            SshMessage::ChannelOpenFailure {
                reason_code: VarInt::from(3u8),
                description: "denied".into(),
            }
            .encode_into(&mut server_writer)
            .await
            .unwrap();
        });

        let err = open_session_channel(client_reader, client_writer, 1)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ClientSessionError::ChannelOpenFailure {
                reason_code: 3,
                description,
            } if description == "denied"
        ));

        server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 2: exec request hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_data_hex_dump() {
        let data = encode_request_data(&ExecRequest {
            command: b"hi".to_vec(),
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
        let (mut writer, mut reader) = duplex(8192);
        send_exec_request(&mut writer, b"echo hello", true)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                assert_eq!(request_type, "exec");
                assert!(want_reply);
                // Verify request_data decodes to "echo hello"
                let req = ExecRequest::decode_from(request_data.as_slice())
                    .await
                    .unwrap();
                assert_eq!(req.command, b"echo hello");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_request_data_allows_non_utf8_bytes() {
        let data = encode_request_data(&ExecRequest {
            command: vec![0x66, 0x6f, 0xff],
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
        let (mut writer, mut reader) = duplex(8192);
        send_shell_request(&mut writer, true).await.unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                assert_eq!(request_type, "shell");
                assert!(want_reply);
                assert!(request_data.is_empty());
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 5: pty-req request roundtrip with server parser
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pty_request_roundtrip() {
        let data = encode_request_data(&PtyRequest {
            term_type: "xterm-256color".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 640,
            height_px: 480,
            terminal_modes: vec![0x01, 0x00, 0x00, 0x00, 0x03],
        })
        .await
        .unwrap();

        // Parse with server's parser
        let parsed = PtyRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(parsed.term_type, "xterm-256color");
        assert_eq!(parsed.width_cols, 80);
        assert_eq!(parsed.height_rows, 24);
        assert_eq!(parsed.width_px, 640);
        assert_eq!(parsed.height_px, 480);
        assert_eq!(parsed.terminal_modes, vec![0x01, 0x00, 0x00, 0x00, 0x03]);
    }

    // -------------------------------------------------------------------
    // Test 6: window-change request roundtrip with server parser
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn window_change_roundtrip() {
        let data = encode_request_data(&WindowChangeRequest {
            width_cols: 120,
            height_rows: 40,
            width_px: 960,
            height_px: 800,
        })
        .await
        .unwrap();

        let parsed = WindowChangeRequest::decode_from(data.as_slice())
            .await
            .unwrap();
        assert_eq!(parsed.width_cols, 120);
        assert_eq!(parsed.height_rows, 40);
        assert_eq!(parsed.width_px, 960);
        assert_eq!(parsed.height_px, 800);
    }

    // -------------------------------------------------------------------
    // Test 7: ChannelData → SessionEvent::Stdout
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn channel_data_to_stdout() {
        let msg = SshMessage::ChannelData {
            data: b"hello\n".to_vec(),
        };
        let event = message_to_session_event(msg).await.unwrap();
        assert_eq!(event, Some(SessionEvent::Stdout(b"hello\n".to_vec())));
    }

    // -------------------------------------------------------------------
    // Test 8: ChannelExtendedData(type=1) → SessionEvent::Stderr
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn stderr_via_extended_data() {
        let msg = SshMessage::ChannelExtendedData {
            data_type: VarInt::from(1u8),
            data: b"error output".to_vec(),
        };
        let event = message_to_session_event(msg).await.unwrap();
        assert_eq!(event, Some(SessionEvent::Stderr(b"error output".to_vec())));
    }

    // -------------------------------------------------------------------
    // Test 9: exit-status extraction
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_extraction() {
        let request_data = encode_request_data(&ExitStatusRequest { exit_status: 42 })
            .await
            .unwrap();
        let msg = SshMessage::ChannelRequest {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data,
        };
        let event = message_to_session_event(msg).await.unwrap();
        assert_eq!(event, Some(SessionEvent::ExitStatus(42)));
    }

    // -------------------------------------------------------------------
    // Test 10: exit-status zero
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_zero() {
        let request_data = encode_request_data(&ExitStatusRequest { exit_status: 0 })
            .await
            .unwrap();
        let code = ExitStatusRequest::decode_from(request_data.as_slice())
            .await
            .unwrap()
            .exit_status;
        assert_eq!(code, 0);
    }

    // -------------------------------------------------------------------
    // Test 11: exit-status 255
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_255() {
        let request_data = encode_request_data(&ExitStatusRequest { exit_status: 255 })
            .await
            .unwrap();
        let code = ExitStatusRequest::decode_from(request_data.as_slice())
            .await
            .unwrap()
            .exit_status;
        assert_eq!(code, 255);
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
        let eof_event = message_to_session_event(SshMessage::ChannelEof)
            .await
            .unwrap();
        assert_eq!(eof_event, Some(SessionEvent::Eof));

        let close_event = message_to_session_event(SshMessage::ChannelClose)
            .await
            .unwrap();
        assert_eq!(close_event, Some(SessionEvent::Close));
    }

    // -------------------------------------------------------------------
    // Test 14: Success and Failure events
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn success_and_failure_events() {
        let success = message_to_session_event(SshMessage::ChannelSuccess)
            .await
            .unwrap();
        assert_eq!(success, Some(SessionEvent::Success));

        let failure = message_to_session_event(SshMessage::ChannelFailure)
            .await
            .unwrap();
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
            SshMessage::ChannelSuccess
                .encode_into(&mut server_writer)
                .await
                .unwrap();
            SshMessage::ChannelData {
                data: b"hello\n".to_vec(),
            }
            .encode_into(&mut server_writer)
            .await
            .unwrap();

            let exit_data = encode_request_data(&ExitStatusRequest { exit_status: 0 })
                .await
                .unwrap();
            SshMessage::ChannelRequest {
                request_type: "exit-status".into(),
                want_reply: false,
                request_data: exit_data,
            }
            .encode_into(&mut server_writer)
            .await
            .unwrap();

            SshMessage::ChannelEof
                .encode_into(&mut server_writer)
                .await
                .unwrap();
            SshMessage::ChannelClose
                .encode_into(&mut server_writer)
                .await
                .unwrap();

            drop(server_writer);
        });

        // Client reads and converts to SessionEvents
        let mut events = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => {
                    if let Some(event) = message_to_session_event(msg).await.unwrap() {
                        events.push(event);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
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
        let (mut writer, mut reader) = duplex(8192);
        send_pty_request(&mut writer, "xterm", 80, 24, 0, 0, &[], true)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                assert_eq!(request_type, "pty-req");
                assert!(want_reply);
                let parsed = PtyRequest::decode_from(request_data.as_slice())
                    .await
                    .unwrap();
                assert_eq!(parsed.term_type, "xterm");
                assert_eq!(parsed.width_cols, 80);
                assert_eq!(parsed.height_rows, 24);
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 17: send_window_change wire format
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_window_change_wire_format() {
        let (mut writer, mut reader) = duplex(8192);
        send_window_change(&mut writer, 120, 40, 960, 800)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                assert_eq!(request_type, "window-change");
                assert!(!want_reply, "window-change must have want_reply=false");
                let parsed = WindowChangeRequest::decode_from(request_data.as_slice())
                    .await
                    .unwrap();
                assert_eq!(parsed.width_cols, 120);
                assert_eq!(parsed.height_rows, 40);
                assert_eq!(parsed.width_px, 960);
                assert_eq!(parsed.height_px, 800);
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_signal_request_wire_format() {
        let (mut writer, mut reader) = duplex(8192);
        send_signal_request(&mut writer, "TERM", false)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                assert_eq!(request_type, "signal");
                assert!(!want_reply);
                let parsed = SignalRequest::decode_from(request_data.as_slice())
                    .await
                    .unwrap();
                assert_eq!(parsed.signal_name, "TERM");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
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
        assert_eq!(
            data,
            SshMessage::ChannelData {
                data: b"hello".to_vec(),
            }
        );
        let eof = SshMessage::decode_from(&mut peer_reader).await.unwrap();
        assert_eq!(eof, SshMessage::ChannelEof);
    }

    #[tokio::test]
    async fn session_channel_expect_success_consumes_reply() {
        let (mut server_writer, client_reader) = duplex(8192);
        let (other_reader, other_writer) = duplex(8192);
        let mut channel = SessionChannel {
            reader: client_reader,
            writer: other_writer,
            max_message_size: VarInt::from(1024u32),
        };

        SshMessage::ChannelSuccess
            .encode_into(&mut server_writer)
            .await
            .unwrap();
        drop(server_writer);

        channel.expect_success().await.unwrap();
        drop(other_reader);
    }

    // -------------------------------------------------------------------
    // Test 18: stderr separated from stdout
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn stderr_separated_from_stdout() {
        let (mut server_writer, mut client_reader) = duplex(8192);

        // Server sends stdout then stderr
        SshMessage::ChannelData {
            data: b"stdout data".to_vec(),
        }
        .encode_into(&mut server_writer)
        .await
        .unwrap();
        SshMessage::ChannelExtendedData {
            data_type: VarInt::from(1u8),
            data: b"stderr data".to_vec(),
        }
        .encode_into(&mut server_writer)
        .await
        .unwrap();
        drop(server_writer);

        // Read messages and separate stdout/stderr
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => {
                    if let Some(event) = message_to_session_event(msg).await.unwrap() {
                        match event {
                            SessionEvent::Stdout(data) => stdout.extend(data),
                            SessionEvent::Stderr(data) => stderr.extend(data),
                            _ => {}
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
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
        let request_data = encode_request_data(&ExitSignalRequest {
            signal_name: "TERM".into(),
            core_dumped: false,
            error_message: "terminated".into(),
            language_tag: "en".into(),
        })
        .await
        .unwrap();
        let msg = SshMessage::ChannelRequest {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        };
        let event = message_to_session_event(msg).await.unwrap();
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
        let request_data = encode_request_data(&ExitSignalRequest {
            signal_name: "SEGV".into(),
            core_dumped: true,
            error_message: "segfault".into(),
            language_tag: String::new(),
        })
        .await
        .unwrap();
        let msg = SshMessage::ChannelRequest {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        };
        let event = message_to_session_event(msg).await.unwrap();
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
            let request_data = encode_request_data(&ExitStatusRequest { exit_status: code })
                .await
                .unwrap();
            let msg = SshMessage::ChannelRequest {
                request_type: "exit-status".into(),
                want_reply: false,
                request_data,
            };
            let event = message_to_session_event(msg).await.unwrap();
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
