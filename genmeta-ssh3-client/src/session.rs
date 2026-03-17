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

use genmeta_ssh3_proto::codec::SshString;
use genmeta_ssh3_proto::message::SshMessage;
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::varint::VarInt;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientExecRequest {
    command: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientPtyRequest {
    term_type: String,
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
    terminal_modes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientWindowChangeRequest {
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientExitStatusRequest {
    exit_status: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientExitSignalRequest {
    signal_name: String,
    core_dumped: bool,
    error_message: String,
    language_tag: String,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ClientExecRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(VarInt::try_from(self.command.len() as u64).map_err(io::Error::other)?)
            .await?;
        stream.write_all(&self.command).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ClientExecRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let len: VarInt = stream.decode_one().await?;
        let mut command = vec![0u8; len.into_inner() as usize];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut command).await?;
        Ok(Self { command })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ClientPtyRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.term_type.clone())).await?;
        stream.encode_one(VarInt::try_from(self.width_cols as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.height_rows as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.width_px as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.height_px as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.terminal_modes.len() as u64).map_err(io::Error::other)?).await?;
        stream.write_all(&self.terminal_modes).await?;
        Ok(())
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ClientWindowChangeRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(VarInt::try_from(self.width_cols as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.height_rows as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.width_px as u64).map_err(io::Error::other)?).await?;
        stream.encode_one(VarInt::try_from(self.height_px as u64).map_err(io::Error::other)?).await?;
        Ok(())
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ClientExitStatusRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(VarInt::try_from(self.exit_status as u64).map_err(io::Error::other)?)
            .await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ClientExitStatusRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let exit_status: VarInt = stream.decode_one().await?;
        Ok(Self {
            exit_status: exit_status.into_inner() as u32,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ClientExitSignalRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.signal_name.clone())).await?;
        stream.write_u8(if self.core_dumped { 0x01 } else { 0x00 }).await?;
        stream.encode_one(SshString(self.error_message.clone())).await?;
        stream.encode_one(SshString(self.language_tag.clone())).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ClientExitSignalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let signal_name: SshString = stream.decode_one().await?;
        let core_dumped = tokio::io::AsyncReadExt::read_u8(&mut stream).await? != 0;
        let error_message: SshString = stream.decode_one().await?;
        let language_tag: SshString = stream.decode_one().await?;
        Ok(Self {
            signal_name: signal_name.0,
            core_dumped,
            error_message: error_message.0,
            language_tag: language_tag.0,
        })
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
) -> io::Result<()> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&ClientExecRequest {
            command: command.to_vec(),
        })
        .await?;
    SshMessage::ChannelRequest {
        request_type: "exec".into(),
        want_reply,
        request_data,
    }.encode_into(writer)
    .await
}

/// Send a ChannelRequest with request_type="shell" (no request_data).
pub async fn send_shell_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    want_reply: bool,
) -> io::Result<()> {
    SshMessage::ChannelRequest {
        request_type: "shell".into(),
        want_reply,
        request_data: vec![],
    }.encode_into(writer)
    .await
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
) -> io::Result<()> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&ClientPtyRequest {
            term_type: term.to_owned(),
            width_cols,
            height_rows,
            width_px,
            height_px,
            terminal_modes: terminal_modes.to_vec(),
        })
        .await?;
    SshMessage::ChannelRequest {
        request_type: "pty-req".into(),
        want_reply,
        request_data,
    }.encode_into(writer)
    .await
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
) -> io::Result<()> {
    let mut request_data = Vec::new();
    request_data
        .encode_one(&ClientWindowChangeRequest {
            width_cols,
            height_rows,
            width_px,
            height_px,
        })
        .await?;
    SshMessage::ChannelRequest {
        request_type: "window-change".into(),
        want_reply: false,
        request_data,
    }.encode_into(writer)
    .await
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
pub async fn message_to_session_event(msg: SshMessage) -> io::Result<Option<SessionEvent>> {
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
                let req = ClientExitStatusRequest::decode_from(request_data.as_slice()).await?;
                Ok(Some(SessionEvent::ExitStatus(req.exit_status)))
            } else if request_type == "exit-signal" {
                let req = ClientExitSignalRequest::decode_from(request_data.as_slice()).await?;
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
    use h3x::codec::{DecodeFrom, EncodeExt};
    use genmeta_ssh3_proto::message::SshMessage;
    use genmeta_ssh3_server::session::pty::{PtyRequest, WindowChangeRequest};
    use genmeta_ssh3_server::session::request::{
        ExecRequest, ExitSignalRequest, ExitStatusRequest, encode_exit_status,
    };
    use tokio::io::{duplex, AsyncReadExt};

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
        let data = encode_request_data(&ClientExecRequest {
            command: b"echo hello".to_vec(),
        })
        .await
        .unwrap();
        let req = ExecRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.command, b"echo hello");
    }

    // -------------------------------------------------------------------
    // Test 2: exec request hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_data_hex_dump() {
        let data = encode_request_data(&ClientExecRequest {
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
                let req = ExecRequest::decode_from(request_data.as_slice()).await.unwrap();
                assert_eq!(req.command, b"echo hello");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_request_data_allows_non_utf8_bytes() {
        let data = encode_request_data(&ClientExecRequest {
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
        let data = encode_request_data(&ClientPtyRequest {
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
        let data = encode_request_data(&ClientWindowChangeRequest {
            width_cols: 120,
            height_rows: 40,
            width_px: 960,
            height_px: 800,
        })
        .await
        .unwrap();

        let parsed = WindowChangeRequest::decode_from(data.as_slice()).await.unwrap();
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
        assert_eq!(
            event,
            Some(SessionEvent::Stderr(b"error output".to_vec()))
        );
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
        let code = ClientExitStatusRequest::decode_from(request_data.as_slice())
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
        let code = ClientExitStatusRequest::decode_from(request_data.as_slice())
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
            SshMessage::ChannelSuccess.encode_into(&mut server_writer)
                .await
                .unwrap();
            SshMessage::ChannelData {
                data: b"hello\n".to_vec(),
            }.encode_into(&mut server_writer)
            .await
            .unwrap();

            let exit_data = encode_request_data(&ExitStatusRequest { exit_status: 0 })
                .await
                .unwrap();
            SshMessage::ChannelRequest {
                request_type: "exit-status".into(),
                want_reply: false,
                request_data: exit_data,
            }.encode_into(&mut server_writer)
            .await
            .unwrap();

            SshMessage::ChannelEof.encode_into(&mut server_writer)
                .await
                .unwrap();
            SshMessage::ChannelClose.encode_into(&mut server_writer)
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
                let parsed = PtyRequest::decode_from(request_data.as_slice()).await.unwrap();
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
                let parsed = WindowChangeRequest::decode_from(request_data.as_slice()).await.unwrap();
                assert_eq!(parsed.width_cols, 120);
                assert_eq!(parsed.height_rows, 40);
                assert_eq!(parsed.width_px, 960);
                assert_eq!(parsed.height_px, 800);
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
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
        }.encode_into(&mut server_writer)
        .await
        .unwrap();
        SshMessage::ChannelExtendedData {
            data_type: VarInt::from(1u8),
            data: b"stderr data".to_vec(),
        }.encode_into(&mut server_writer)
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
