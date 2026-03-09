//! SSH3 session-layer request handling for exec, shell, and subsystem.
//!
//! Processes `ChannelEvent::Request` payloads dispatched from the channel
//! message loop. Supports:
//!
//! - `exec` — run a command via `/bin/sh -c`
//! - `shell` — launch an interactive shell
//! - `subsystem` — rejected (not implemented)

use std::process::Stdio;

use genmeta_ssh3_proto::{codec::SshString, message::SshMessage};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite};

use crate::channel::ChannelEvent;

/// Action returned by [`handle_request`] indicating what the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    /// Run `exec` with the given command string.
    Exec(String),
    /// Launch an interactive shell.
    Shell,
}

/// Parse a `ChannelEvent::Request` and determine the appropriate action.
///
/// For recognized request types (`exec`, `shell`), sends `ChannelSuccess` if
/// `want_reply` is true, then returns the action. For unrecognized or
/// unsupported types (`subsystem`, etc.), sends `ChannelFailure` and returns
/// `Ok(None)`.
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
            let command = parse_exec_command(request_data).await?;
            if want_reply {
                SshMessage::encode(&SshMessage::ChannelSuccess, writer).await?;
            }
            Ok(Some(RequestAction::Exec(command)))
        }
        "shell" => {
            if want_reply {
                SshMessage::encode(&SshMessage::ChannelSuccess, writer).await?;
            }
            Ok(Some(RequestAction::Shell))
        }
        "subsystem" | _ if request_type == "subsystem" => {
            if want_reply {
                SshMessage::encode(&SshMessage::ChannelFailure, writer).await?;
            }
            Ok(None)
        }
        _ => {
            // Unknown request type — send failure if reply requested.
            if want_reply {
                SshMessage::encode(&SshMessage::ChannelFailure, writer).await?;
            }
            Ok(None)
        }
    }
}

/// Spawn `/bin/sh -c <command>`, copy stdout → ChannelData, stderr →
/// ChannelExtendedData, then send exit-status + EOF + Close.
pub async fn run_exec<W>(command: &str, writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let mut child = match tokio::process::Command::new("/bin/sh")
        .args(["-c", command])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::error!(%e, "failed to spawn command");
            SshMessage::encode(&SshMessage::ChannelFailure, writer).await?;
            return Err(e);
        }
    };

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    // Read stdout and stderr concurrently, sending as channel messages.
    let (stdout_result, stderr_result) = tokio::join!(
        copy_stream_to_channel_data(&mut stdout, writer),
        read_all_stderr(&mut stderr),
    );

    // Send any stderr data as ChannelExtendedData.
    let stderr_data = stderr_result?;
    if !stderr_data.is_empty() {
        SshMessage::encode(
            &SshMessage::ChannelExtendedData {
                data_type: 1,
                data: stderr_data,
            },
            writer,
        )
        .await?;
    }

    stdout_result?;

    // Wait for process to exit.
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(255) as u32;

    // Send exit-status request.
    let exit_data = encode_exit_status(exit_code);
    SshMessage::encode(
        &SshMessage::ChannelRequest {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data: exit_data,
        },
        writer,
    )
    .await?;

    // Send EOF + Close.
    SshMessage::encode(&SshMessage::ChannelEof, writer).await?;
    SshMessage::encode(&SshMessage::ChannelClose, writer).await?;

    Ok(())
}

/// Launch an interactive shell, copy stdout → ChannelData, stderr →
/// ChannelExtendedData, then send exit-status + EOF + Close.
pub async fn run_shell<W>(shell_path: &str, writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let mut child = match tokio::process::Command::new(shell_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::error!(%e, "failed to spawn shell");
            SshMessage::encode(&SshMessage::ChannelFailure, writer).await?;
            return Err(e);
        }
    };

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    let (stdout_result, stderr_result) = tokio::join!(
        copy_stream_to_channel_data(&mut stdout, writer),
        read_all_stderr(&mut stderr),
    );

    let stderr_data = stderr_result?;
    if !stderr_data.is_empty() {
        SshMessage::encode(
            &SshMessage::ChannelExtendedData {
                data_type: 1,
                data: stderr_data,
            },
            writer,
        )
        .await?;
    }

    stdout_result?;

    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(255) as u32;

    let exit_data = encode_exit_status(exit_code);
    SshMessage::encode(
        &SshMessage::ChannelRequest {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data: exit_data,
        },
        writer,
    )
    .await?;

    SshMessage::encode(&SshMessage::ChannelEof, writer).await?;
    SshMessage::encode(&SshMessage::ChannelClose, writer).await?;

    Ok(())
}

/// Encode an exit code as QUIC VarInt bytes for the exit-status request_data.
///
/// Uses the QUIC variable-length integer encoding:
/// - Values 0–63: 1 byte (6-bit value, top 2 bits = 00)
/// - Values 64–16383: 2 bytes (14-bit value, top 2 bits = 01)
/// - Values 16384–1073741823: 4 bytes (30-bit value, top 2 bits = 10)
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
        // Should not happen for exit codes, but handle gracefully.
        let val = 0xC000_0000_0000_0000u64 | v;
        val.to_be_bytes().to_vec()
    }
}

/// Parse an exec command from request_data bytes.
///
/// The command is encoded as an `SshString` (varint length prefix + UTF-8 bytes).
pub async fn parse_exec_command(request_data: &[u8]) -> io::Result<String> {
    let mut reader = request_data;
    let ssh_string = SshString::decode(&mut reader).await?;
    Ok(ssh_string.0)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read from an `AsyncRead` and send chunks as `SshMessage::ChannelData`.
///
/// Note: Since we can't share `&mut W` across tasks, stdout is read inline
/// and stderr is buffered separately.
async fn copy_stream_to_channel_data<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        SshMessage::encode(
            &SshMessage::ChannelData {
                data: buf[..n].to_vec(),
            },
            writer,
        )
        .await?;
    }
    Ok(())
}

/// Read all data from an `AsyncRead` into a buffer (used for stderr).
async fn read_all_stderr<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Send + Unpin,
{
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::{codec::SshString, message::SshMessage};
    use tokio::io::duplex;

    // -------------------------------------------------------------------
    // Test 1: parse_exec_command parses SshString from bytes
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_exec_command_simple() {
        // Encode "echo hello" as SshString
        let (mut writer, mut reader) = duplex(4096);
        SshString("echo hello".into()).encode(&mut writer).await.unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let cmd = parse_exec_command(&buf).await.unwrap();
        assert_eq!(cmd, "echo hello");
    }

    #[tokio::test]
    async fn parse_exec_command_empty() {
        // Encode empty string as SshString
        let (mut writer, mut reader) = duplex(4096);
        SshString(String::new()).encode(&mut writer).await.unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let cmd = parse_exec_command(&buf).await.unwrap();
        assert_eq!(cmd, "");
    }

    // -------------------------------------------------------------------
    // Test 2: encode_exit_status produces correct VarInt bytes
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn encode_exit_status_zero() {
        let bytes = encode_exit_status(0);
        assert_eq!(bytes, vec![0x00]);
    }

    #[tokio::test]
    async fn encode_exit_status_one() {
        let bytes = encode_exit_status(1);
        assert_eq!(bytes, vec![0x01]);
    }

    #[tokio::test]
    async fn encode_exit_status_small() {
        // 42 < 64 → 1 byte
        let bytes = encode_exit_status(42);
        assert_eq!(bytes, vec![42]);
    }

    #[tokio::test]
    async fn encode_exit_status_two_byte() {
        // 127 >= 64, < 16384 → 2 bytes: [0x40 | (127>>8), 127&0xff] = [0x40, 0x7f]
        let bytes = encode_exit_status(127);
        assert_eq!(bytes, vec![0x40, 0x7f]);
    }

    #[tokio::test]
    async fn encode_exit_status_255() {
        // 255 >= 64, < 16384 → 2 bytes: [0x40 | (255>>8), 255&0xff] = [0x40, 0xff]
        let bytes = encode_exit_status(255);
        assert_eq!(bytes, vec![0x40, 0xff]);
    }

    // -------------------------------------------------------------------
    // Test 3: exec_echo — full lifecycle test
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_echo() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        // Run "echo hello" and capture all output.
        run_exec("echo hello", &mut server_writer).await.unwrap();
        drop(server_writer);

        // Collect all messages sent to the client.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // Should have at least: ChannelData("hello\n"), exit-status request, EOF, Close
        assert!(
            messages.len() >= 3,
            "expected at least 3 messages, got {}: {messages:?}",
            messages.len()
        );

        // Find the ChannelData containing "hello"
        let has_hello = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("hello")
            }
            _ => false,
        });
        assert!(has_hello, "expected ChannelData containing 'hello', got: {messages:?}");

        // Check exit-status request
        let has_exit_status = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                request_type == "exit-status"
                    && !want_reply
                    && *request_data == encode_exit_status(0)
            }
            _ => false,
        });
        assert!(
            has_exit_status,
            "expected exit-status request with code 0, got: {messages:?}"
        );

        // Check EOF and Close are present
        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)),
            "expected ChannelEof"
        );
        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)),
            "expected ChannelClose"
        );

        // Verify ordering: exit-status comes before EOF, EOF before Close
        let exit_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::ChannelRequest { request_type, .. } if request_type == "exit-status"))
            .unwrap();
        let eof_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::ChannelEof))
            .unwrap();
        let close_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::ChannelClose))
            .unwrap();
        assert!(
            exit_pos < eof_pos,
            "exit-status should come before EOF"
        );
        assert!(
            eof_pos < close_pos,
            "EOF should come before Close"
        );
    }

    // -------------------------------------------------------------------
    // Test 4: exec_failure — nonexistent command sends proper exit code
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_failure() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        // Run a command that will fail (nonexistent binary).
        run_exec("__nonexistent_command_xyz_2024__", &mut server_writer)
            .await
            .unwrap();
        drop(server_writer);

        // Collect all messages.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // Should have exit-status with non-zero code, EOF, Close.
        let has_nonzero_exit = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                request_type == "exit-status"
                    && !want_reply
                    && *request_data != encode_exit_status(0)
            }
            _ => false,
        });
        assert!(
            has_nonzero_exit,
            "expected exit-status with non-zero code, got: {messages:?}"
        );

        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)),
            "expected ChannelEof"
        );
        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)),
            "expected ChannelClose"
        );
    }

    // -------------------------------------------------------------------
    // Test 5: subsystem_rejected — subsystem request → ChannelFailure
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn subsystem_rejected() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let event = ChannelEvent::Request {
            request_type: "subsystem".into(),
            want_reply: true,
            request_data: b"sftp".to_vec(),
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, None, "subsystem should return None");

        drop(server_writer);

        // Should have sent ChannelFailure.
        let msg = SshMessage::decode(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::ChannelFailure);
    }

    // -------------------------------------------------------------------
    // Additional: handle_request dispatches exec correctly
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exec() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        // Build request_data containing SshString("ls -la")
        let (mut enc_writer, mut enc_reader) = duplex(4096);
        SshString("ls -la".into()).encode(&mut enc_writer).await.unwrap();
        drop(enc_writer);
        let mut request_data = Vec::new();
        enc_reader.read_to_end(&mut request_data).await.unwrap();

        let event = ChannelEvent::Request {
            request_type: "exec".into(),
            want_reply: true,
            request_data,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Exec("ls -la".into())));

        drop(server_writer);

        // Should have sent ChannelSuccess (want_reply=true).
        let msg = SshMessage::decode(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::ChannelSuccess);
    }

    #[tokio::test]
    async fn handle_request_shell() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let event = ChannelEvent::Request {
            request_type: "shell".into(),
            want_reply: true,
            request_data: vec![],
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Shell));

        drop(server_writer);

        let msg = SshMessage::decode(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::ChannelSuccess);
    }

    #[tokio::test]
    async fn handle_request_unknown_type() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let event = ChannelEvent::Request {
            request_type: "x11-req".into(),
            want_reply: true,
            request_data: vec![],
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, None);

        drop(server_writer);

        let msg = SshMessage::decode(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::ChannelFailure);
    }

    #[tokio::test]
    async fn handle_request_no_reply() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let event = ChannelEvent::Request {
            request_type: "shell".into(),
            want_reply: false,
            request_data: vec![],
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Shell));

        drop(server_writer);

        // No reply should have been sent.
        let result = SshMessage::decode(&mut client_reader).await;
        assert!(
            result.is_err(),
            "no message should be sent when want_reply=false"
        );
    }

    #[tokio::test]
    async fn handle_request_non_request_event() {
        let (server_writer, _client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let event = ChannelEvent::Data(b"hello".to_vec());
        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, None, "non-Request events should return None");
    }
}
