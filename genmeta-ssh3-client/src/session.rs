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
use h3x::codec::{DecodeExt, EncodeExt, EncodeInto};
use h3x::varint::VarInt;
use tokio::io::{self, AsyncWrite, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Session request_data encoders
// ---------------------------------------------------------------------------

/// Encode an exec request_data: `SshString(command)`.
///
/// The server will parse this with `parse_exec_command` (Task 16).
pub async fn encode_exec_request_data(command: &str) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    SshString(command.to_owned()).encode_into(&mut buf).await?;
    Ok(buf)
}

/// Encode a pty-req request_data (RFC 4254 §6.2):
///
/// - `SshString(term)` — TERM environment variable
/// - `VarInt(width_cols)` — terminal width in characters
/// - `VarInt(height_rows)` — terminal height in rows
/// - `VarInt(width_px)` — terminal width in pixels
/// - `VarInt(height_px)` — terminal height in pixels
/// - varint-length-prefixed bytes — encoded terminal modes
pub async fn encode_pty_request_data(
    term: &str,
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
    terminal_modes: &[u8],
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    SshString(term.to_owned()).encode_into(&mut buf).await?;

    let to_varint =
        |v: u32| VarInt::try_from(v as u64).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e));

    buf.encode_one(to_varint(width_cols)?).await?;
    buf.encode_one(to_varint(height_rows)?).await?;
    buf.encode_one(to_varint(width_px)?).await?;
    buf.encode_one(to_varint(height_px)?).await?;

    // Terminal modes: varint length prefix + raw bytes.
    let modes_len = VarInt::try_from(terminal_modes.len() as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(modes_len).await?;
    buf.write_all(terminal_modes).await?;

    Ok(buf)
}

/// Encode a window-change request_data (RFC 4254 §6.7):
///
/// - `VarInt(width_cols)` — terminal width in columns
/// - `VarInt(height_rows)` — terminal height in rows
/// - `VarInt(width_px)` — terminal width in pixels
/// - `VarInt(height_px)` — terminal height in pixels
pub async fn encode_window_change_request_data(
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();

    let to_varint =
        |v: u32| VarInt::try_from(v as u64).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e));

    buf.encode_one(to_varint(width_cols)?).await?;
    buf.encode_one(to_varint(height_rows)?).await?;
    buf.encode_one(to_varint(width_px)?).await?;
    buf.encode_one(to_varint(height_px)?).await?;

    Ok(buf)
}

// ---------------------------------------------------------------------------
// Sending session requests
// ---------------------------------------------------------------------------

/// Send a ChannelRequest with request_type="exec" and the given command.
pub async fn send_exec_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    command: &str,
    want_reply: bool,
) -> io::Result<()> {
    let request_data = encode_exec_request_data(command).await?;
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
    let request_data =
        encode_pty_request_data(term, width_cols, height_rows, width_px, height_px, terminal_modes)
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
    let request_data =
        encode_window_change_request_data(width_cols, height_rows, width_px, height_px).await?;
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
    /// The server signaled end-of-file.
    Eof,
    /// The server closed the channel.
    Close,
    /// ChannelSuccess — reply to a want_reply=true request.
    Success,
    /// ChannelFailure — reply to a want_reply=true request.
    Failure,
}

/// Parse an exit-status from the request_data of a ChannelRequest
/// with request_type="exit-status".
///
/// The exit code is encoded as a VarInt.
pub async fn parse_exit_status(request_data: &[u8]) -> io::Result<u32> {
    let mut reader = request_data;
    let exit_status: VarInt = reader.decode_one().await?;
    Ok(exit_status.into_inner() as u32)
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
                let code = parse_exit_status(&request_data).await?;
                Ok(Some(SessionEvent::ExitStatus(code)))
            } else if request_type == "exit-signal" {
                // For now, treat exit-signal as exit code 255 (killed by signal).
                Ok(Some(SessionEvent::ExitStatus(255)))
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::codec::DecodeFrom;
    use genmeta_ssh3_proto::message::SshMessage;
    use genmeta_ssh3_server::session::request::{
        encode_exit_status, encode_exit_status_data, parse_exec_command,
    };
    use genmeta_ssh3_server::session::pty::{parse_pty_request, parse_window_change};
    use tokio::io::duplex;

    // -------------------------------------------------------------------
    // Test 1: exec request encoding verified against server's parser
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_data_roundtrip() {
        let data = encode_exec_request_data("echo hello").await.unwrap();
        // The server parses this with parse_exec_command
        let cmd = parse_exec_command(&data).await.unwrap();
        assert_eq!(cmd, "echo hello");
    }

    // -------------------------------------------------------------------
    // Test 2: exec request hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_data_hex_dump() {
        let data = encode_exec_request_data("hi").await.unwrap();
        // "hi": varint(2)=0x02, b"hi"=[0x68, 0x69]
        assert_eq!(data, vec![0x02, 0x68, 0x69]);
    }

    // -------------------------------------------------------------------
    // Test 3: send_exec_request produces correct ChannelRequest(98)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_remote_command() {
        let (mut writer, mut reader) = duplex(8192);
        send_exec_request(&mut writer, "echo hello", true)
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
                let cmd = parse_exec_command(&request_data).await.unwrap();
                assert_eq!(cmd, "echo hello");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
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
        let data = encode_pty_request_data(
            "xterm-256color",
            80,
            24,
            640,
            480,
            &[0x01, 0x00, 0x00, 0x00, 0x03],
        )
        .await
        .unwrap();

        // Parse with server's parser
        let parsed = parse_pty_request(&data).await.unwrap();
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
        let data =
            encode_window_change_request_data(120, 40, 960, 800)
                .await
                .unwrap();

        let parsed = parse_window_change(&data).await.unwrap();
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
        let request_data = encode_exit_status_data(42).await.unwrap();
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
        let request_data = encode_exit_status_data(0).await.unwrap();
        let code = parse_exit_status(&request_data).await.unwrap();
        assert_eq!(code, 0);
    }

    // -------------------------------------------------------------------
    // Test 11: exit-status 255
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_255() {
        let request_data = encode_exit_status_data(255).await.unwrap();
        let code = parse_exit_status(&request_data).await.unwrap();
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

            let exit_data = encode_exit_status_data(0).await.unwrap();
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
                let parsed = parse_pty_request(&request_data).await.unwrap();
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
                let parsed = parse_window_change(&request_data).await.unwrap();
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
}
