//! SSH3 session-layer request handling for exec, shell, subsystem, exit-status,
//! and exit-signal.
//!
//! Processes `ChannelEvent::Request` payloads dispatched from the channel
//! message loop. Supports:
//!
//! - `exec` — run a command via `/bin/sh -c`
//! - `shell` — launch an interactive shell
//! - `subsystem` — rejected (not implemented)
//! - `exit-status` — process exit code (server→client direction)
//! - `exit-signal` — process killed by signal (server→client direction)

use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::ffi::OsStr;
use std::process::Stdio;

fn default_shell() -> &'static OsStr {
    OsStr::new("/bin/sh")
}

use genmeta_ssh3_proto::{codec::SshString, message::SshMessage};
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use snafu::Report;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::channel::ChannelEvent;
use crate::session::pty::{
    PtyPair, PtyRequest, SignalRequest, WindowChangeRequest,
    parse_pty_request, parse_signal, parse_window_change, set_window_size,
};
// ---------------------------------------------------------------------------
// Parsed request types
// ---------------------------------------------------------------------------

/// Parsed exec request: a command string to execute via `/bin/sh -c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: String,
}

/// Parsed subsystem request: the subsystem name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemRequest {
    pub subsystem_name: String,
}

/// Parsed exit-status request: the process exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatusRequest {
    pub exit_status: u32,
}

/// Parsed exit-signal request (RFC 4254 §6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignalRequest {
    pub signal_name: String,
    pub core_dumped: bool,
    pub error_message: String,
    pub language_tag: String,
}

/// Action returned by [`handle_request`] indicating what the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    /// Run `exec` with the given command string.
    Exec(String),
    /// Launch an interactive shell.
    Shell,
    /// Allocate a PTY with the given parameters.
    AllocatePty(PtyRequest),
    /// Resize the terminal window.
    WindowChange(WindowChangeRequest),
    /// Deliver a signal to the running process.
    Signal(SignalRequest),
}

// ---------------------------------------------------------------------------
// Request data parsing
// ---------------------------------------------------------------------------

/// Parse an exec command from request_data bytes.
///
/// The command is encoded as an `SshString` (varint length prefix + UTF-8 bytes).
pub async fn parse_exec_command(request_data: &[u8]) -> io::Result<String> {
    let mut reader = request_data;
    let ssh_string = SshString::decode_from(&mut reader).await?;
    Ok(ssh_string.0)
}

/// Parse a subsystem name from request_data bytes.
///
/// The subsystem name is encoded as an `SshString`.
pub async fn parse_subsystem_request(request_data: &[u8]) -> io::Result<SubsystemRequest> {
    let mut reader = request_data;
    let subsystem_name = SshString::decode_from(&mut reader).await?;
    Ok(SubsystemRequest {
        subsystem_name: subsystem_name.0,
    })
}

/// Parse exit-status request_data: a uint32 encoded as VarInt.
pub async fn parse_exit_status_request(request_data: &[u8]) -> io::Result<ExitStatusRequest> {
    let mut reader = request_data;
    let exit_status: VarInt = reader.decode_one().await?;
    Ok(ExitStatusRequest {
        exit_status: exit_status.into_inner() as u32,
    })
}

/// Parse exit-signal request_data: signal_name(SshString) + core_dumped(bool byte) +
/// error_message(SshString) + language_tag(SshString).
pub async fn parse_exit_signal_request(request_data: &[u8]) -> io::Result<ExitSignalRequest> {
    let mut reader = request_data;
    let signal_name = SshString::decode_from(&mut reader).await?;
    // core_dumped is a single byte boolean (0x00 or 0x01), matching SshBool encoding.
    let core_dumped_byte = AsyncReadExt::read_u8(&mut reader).await?;
    let core_dumped = core_dumped_byte != 0;
    let error_message = SshString::decode_from(&mut reader).await?;
    let language_tag = SshString::decode_from(&mut reader).await?;
    Ok(ExitSignalRequest {
        signal_name: signal_name.0,
        core_dumped,
        error_message: error_message.0,
        language_tag: language_tag.0,
    })
}

// ---------------------------------------------------------------------------
// Exit-status/exit-signal encoding (for sending from server)
// ---------------------------------------------------------------------------

/// Encode an exit code as QUIC VarInt bytes for the exit-status request_data.
pub async fn encode_exit_status_data(exit_code: u32) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let varint = VarInt::try_from(exit_code as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(varint).await?;
    Ok(buf)
}

/// Synchronous version of exit-status encoding for use in assertions.
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

/// Encode exit-signal request_data.
pub async fn encode_exit_signal_data(
    signal_name: &str,
    core_dumped: bool,
    error_message: &str,
    language_tag: &str,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    SshString(signal_name.to_owned()).encode_into(&mut buf).await?;
    buf.write_u8(if core_dumped { 0x01 } else { 0x00 }).await?;
    SshString(error_message.to_owned()).encode_into(&mut buf).await?;
    SshString(language_tag.to_owned()).encode_into(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

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
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::Exec(command)))
        }
        "shell" => {
            if want_reply {
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::Shell))
        }
        "pty-req" => {
            let req = parse_pty_request(request_data).await?;
            if want_reply {
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::AllocatePty(req)))
        }
        "window-change" => {
            let req = parse_window_change(request_data).await?;
            if want_reply {
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::WindowChange(req)))
        }
        "signal" => {
            let req = parse_signal(request_data).await?;
            if want_reply {
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::Signal(req)))
        }
        "subsystem" => {
            // MVP: subsystem not implemented, return failure.
            let _req = parse_subsystem_request(request_data).await?;
            if want_reply {
                SshMessage::ChannelFailure.encode_into(writer).await?;
            }
            Ok(None)
        }
        "exit-status" => {
            // Server→client direction: parse and acknowledge (no action needed).
            let _req = parse_exit_status_request(request_data).await?;
            Ok(None)
        }
        "exit-signal" => {
            // Server→client direction: parse and acknowledge (no action needed).
            let _req = parse_exit_signal_request(request_data).await?;
            Ok(None)
        }
        _ => {
            // Unknown request type — send failure if reply requested.
            if want_reply {
                SshMessage::ChannelFailure.encode_into(writer).await?;
            }
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Exec/Shell/Subsystem handlers
// ---------------------------------------------------------------------------

/// Spawn `/bin/sh -c <command>`, copy stdout → ChannelData, stderr →
/// ChannelExtendedData, then send exit-status + EOF + Close.
///
/// When `pty` is `Some`, the child process uses the PTY slave as stdin/stdout/stderr,
/// and the PTY master is used for I/O relay.
pub async fn run_exec<W>(
    command: &str,
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
    pty: Option<PtyPair>,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    if let Some(pty_pair) = pty {
        run_command_with_pty(default_shell(), &["-c", command], writer, event_rx, pty_pair).await
    } else {
        run_command_piped(default_shell(), &["-c", command], writer, event_rx).await
    }
}

/// Launch an interactive shell, copy stdout → ChannelData, stderr →
/// ChannelExtendedData, then send exit-status + EOF + Close.
///
/// When `pty` is `Some`, the child process uses the PTY slave as stdin/stdout/stderr,
/// and the PTY master is used for I/O relay.
pub async fn run_shell<W>(
    shell_path: &OsStr,
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
    pty: Option<PtyPair>,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    if let Some(pty_pair) = pty {
        run_command_with_pty(shell_path, &[], writer, event_rx, pty_pair).await
    } else {
        run_command_piped(shell_path, &[], writer, event_rx).await
    }
}

/// Run a command with piped stdio (no PTY).
async fn run_command_piped<W>(
    program: &OsStr,
    args: &[&str],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let mut child = match tokio::process::Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to spawn command");
            SshMessage::ChannelFailure.encode_into(writer).await?;
            return Err(e);
        }
    };

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdin = child.stdin.take().unwrap();

    // Spawn a stdin relay task: reads ChannelEvent::Data from event_rx -> writes to stdin.
    let stdin_task = tokio::spawn(async move {
        let mut stdin = stdin;
        let mut event_rx = event_rx;
        while let Some(event) = event_rx.recv().await {
            match event {
                ChannelEvent::Data(data)
                    if stdin.write_all(&data).await.is_err() =>
                {
                    break;
                }
                ChannelEvent::Eof => break,
                _ => {}
            }
        }
        drop(stdin); // Close stdin to signal EOF to child
    }.in_current_span());

    // Read stdout and stderr concurrently, sending as channel messages.
    let (stdout_result, stderr_result) = tokio::join!(
        copy_stream_to_channel_data(&mut stdout, writer),
        read_all_stderr(&mut stderr),
    );

    // Send any stderr data as ChannelExtendedData.
    let stderr_data = stderr_result?;
    if !stderr_data.is_empty() {
        SshMessage::ChannelExtendedData {
            data_type: 1,
            data: stderr_data,
        }.encode_into(&mut *writer)
        .await?;
    }

    stdout_result?;

    // Wait for process to exit.
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(255) as u32;

    // Send exit-status request.
    send_exit_status(exit_code, writer).await?;

    // Send EOF + Close.
    SshMessage::ChannelEof.encode_into(&mut *writer).await?;
    SshMessage::ChannelClose.encode_into(&mut *writer).await?;
    writer.shutdown().await?;

    // Clean up stdin relay task.
    stdin_task.abort();
    let _ = stdin_task.await;

    Ok(())
}

/// Run a command with PTY: child uses slave as stdin/stdout/stderr,
/// master is used for I/O relay.
async fn run_command_with_pty<W>(
    program: &OsStr,
    args: &[&str],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
    pty_pair: PtyPair,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    // Duplicate the slave fd for stdout and stderr before consuming for stdin.
    let slave_raw = pty_pair.slave.as_raw_fd();
    let stdout_fd = unsafe { libc::dup(slave_raw) };
    if stdout_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stderr_fd = unsafe { libc::dup(slave_raw) };
    if stderr_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stdin_fd = pty_pair.slave.into_raw_fd();

    let mut child = match tokio::process::Command::new(program)
        .args(args)
        .stdin(unsafe { Stdio::from_raw_fd(stdin_fd) })
        .stdout(unsafe { Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { Stdio::from_raw_fd(stderr_fd) })
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to spawn command with PTY");
            SshMessage::ChannelFailure.encode_into(writer).await?;
            return Err(e);
        }
    };

    // Get child PID for signal delivery.
    let child_pid = child.id().unwrap_or(0) as i32;

    // Wrap PTY master into async file for reading/writing.
    let master_raw_fd = pty_pair.master.as_raw_fd();
    let master_file = std::fs::File::from(pty_pair.master);
    let master_tokio = tokio::fs::File::from(master_file);
    let (mut master_reader, master_writer) = tokio::io::split(master_tokio);

    // Spawn stdin relay task: reads ChannelEvent::Data -> writes to PTY master,
    // handles Signal and WindowChange events.
    let stdin_task = tokio::spawn(async move {
        let mut master_writer = master_writer;
        let mut event_rx = event_rx;
        while let Some(event) = event_rx.recv().await {
            match event {
                ChannelEvent::Data(data)
                    if master_writer.write_all(&data).await.is_err() =>
                {
                    break;
                }
                ChannelEvent::Request {
                    request_type,
                    request_data,
                    ..
                } => {
                    match request_type.as_str() {
                        "signal" => {
                            if let Ok(req) = parse_signal(&request_data).await
                                && child_pid > 0
                            {
                                let sig = match req.signal_name.as_str() {
                                    "HUP" => Some(libc::SIGHUP),
                                    "INT" => Some(libc::SIGINT),
                                    "QUIT" => Some(libc::SIGQUIT),
                                    "KILL" => Some(libc::SIGKILL),
                                    "TERM" => Some(libc::SIGTERM),
                                    "USR1" => Some(libc::SIGUSR1),
                                    "USR2" => Some(libc::SIGUSR2),
                                    _ => None,
                                };
                                if let Some(sig) = sig {
                                    unsafe { libc::kill(child_pid, sig) };
                                }
                            }
                        }
                        "window-change" => {
                            if let Ok(req) = parse_window_change(&request_data).await {
                                let _ = set_window_size(master_raw_fd, &req);
                            }
                        }
                        _ => {}
                    }
                }
                ChannelEvent::Eof => break,
                _ => {}
            }
        }
        drop(master_writer);
    }.in_current_span());

    // Read from PTY master → ChannelData (PTY combines stdout+stderr).
    let stdout_result = copy_stream_to_channel_data(&mut master_reader, writer).await;

    // EIO is expected when the child exits and the slave side closes.
    if let Err(ref e) = stdout_result
        && e.raw_os_error() != Some(libc::EIO)
    {
        stdout_result?;
    }

    // Wait for process to exit.
    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(255) as u32;

    // Send exit-status request.
    send_exit_status(exit_code, writer).await?;

    // Send EOF + Close.
    SshMessage::ChannelEof.encode_into(&mut *writer).await?;
    SshMessage::ChannelClose.encode_into(&mut *writer).await?;
    writer.shutdown().await?;

    // Clean up stdin relay task.
    stdin_task.abort();
    let _ = stdin_task.await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Exit-status/exit-signal sending helpers
// ---------------------------------------------------------------------------

/// Send an exit-status ChannelRequest to the client.
pub async fn send_exit_status<W>(exit_code: u32, writer: &mut W) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let request_data = encode_exit_status_data(exit_code).await?;
    SshMessage::ChannelRequest {
        request_type: "exit-status".into(),
        want_reply: false,
        request_data,
    }.encode_into(writer)
    .await
}

/// Send an exit-signal ChannelRequest to the client.
pub async fn send_exit_signal<W>(
    signal_name: &str,
    core_dumped: bool,
    error_message: &str,
    language_tag: &str,
    writer: &mut W,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let request_data =
        encode_exit_signal_data(signal_name, core_dumped, error_message, language_tag).await?;
    SshMessage::ChannelRequest {
        request_type: "exit-signal".into(),
        want_reply: false,
        request_data,
    }.encode_into(writer)
    .await
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
        SshMessage::ChannelData {
            data: buf[..n].to_vec(),
        }.encode_into(&mut *writer)
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
        SshString("echo hello".into()).encode_into(&mut writer).await.unwrap();
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
        SshString(String::new()).encode_into(&mut writer).await.unwrap();
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
        let (_, rx) = mpsc::channel(1);
        run_exec("echo hello", &mut server_writer, rx, None).await.unwrap();
        drop(server_writer);

        // Collect all messages sent to the client.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
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
        let (_, rx) = mpsc::channel(1);
        run_exec("__nonexistent_command_xyz_2024__", &mut server_writer, rx, None)
            .await
            .unwrap();
        drop(server_writer);

        // Collect all messages.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
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

        // Build SshString-encoded subsystem name for request_data
        let mut request_data_buf = Vec::new();
        SshString("sftp".into()).encode_into(&mut request_data_buf)
            .await
            .unwrap();

        let event = ChannelEvent::Request {
            request_type: "subsystem".into(),
            want_reply: true,
            request_data: request_data_buf,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, None, "subsystem should return None");

        drop(server_writer);

        // Should have sent ChannelFailure.
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::ChannelFailure);
    }

    // -------------------------------------------------------------------
    // Test 6: handle_request dispatches exec correctly
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exec() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        // Build request_data containing SshString("ls -la")
        let (mut enc_writer, mut enc_reader) = duplex(4096);
        SshString("ls -la".into()).encode_into(&mut enc_writer).await.unwrap();
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
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
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

        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
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

        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
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
        let result = SshMessage::decode_from(&mut client_reader).await;
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

    // -------------------------------------------------------------------
    // Test 7: parse_exit_status_request roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_exit_status_roundtrip() {
        let data = encode_exit_status_data(42).await.unwrap();
        let req = parse_exit_status_request(&data).await.unwrap();
        assert_eq!(req.exit_status, 42);
    }

    #[tokio::test]
    async fn parse_exit_status_zero() {
        let data = encode_exit_status_data(0).await.unwrap();
        let req = parse_exit_status_request(&data).await.unwrap();
        assert_eq!(req.exit_status, 0);
    }

    #[tokio::test]
    async fn parse_exit_status_255() {
        let data = encode_exit_status_data(255).await.unwrap();
        let req = parse_exit_status_request(&data).await.unwrap();
        assert_eq!(req.exit_status, 255);
    }

    // -------------------------------------------------------------------
    // Test 8: parse_exit_signal_request roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_exit_signal_roundtrip() {
        let data =
            encode_exit_signal_data("KILL", true, "killed by signal", "en").await.unwrap();
        let req = parse_exit_signal_request(&data).await.unwrap();
        assert_eq!(req.signal_name, "KILL");
        assert!(req.core_dumped);
        assert_eq!(req.error_message, "killed by signal");
        assert_eq!(req.language_tag, "en");
    }

    #[tokio::test]
    async fn parse_exit_signal_no_core_dump() {
        let data =
            encode_exit_signal_data("TERM", false, "terminated", "").await.unwrap();
        let req = parse_exit_signal_request(&data).await.unwrap();
        assert_eq!(req.signal_name, "TERM");
        assert!(!req.core_dumped);
        assert_eq!(req.error_message, "terminated");
        assert_eq!(req.language_tag, "");
    }

    // -------------------------------------------------------------------
    // Test 9: send_exit_status writes correct ChannelRequest
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_exit_status_message() {
        let (mut writer, mut reader) = duplex(8192);
        send_exit_status(42, &mut writer).await.unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                assert_eq!(request_type, "exit-status");
                assert!(!want_reply);
                let req = parse_exit_status_request(&request_data).await.unwrap();
                assert_eq!(req.exit_status, 42);
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 10: send_exit_signal writes correct ChannelRequest
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_exit_signal_message() {
        let (mut writer, mut reader) = duplex(8192);
        send_exit_signal("TERM", false, "terminated", "en", &mut writer)
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
                assert_eq!(request_type, "exit-signal");
                assert!(!want_reply);
                let req = parse_exit_signal_request(&request_data).await.unwrap();
                assert_eq!(req.signal_name, "TERM");
                assert!(!req.core_dumped);
                assert_eq!(req.error_message, "terminated");
                assert_eq!(req.language_tag, "en");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 11: parse_subsystem_request
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_subsystem_name() {
        let mut buf = Vec::new();
        SshString("sftp".into()).encode_into(&mut buf).await.unwrap();
        let req = parse_subsystem_request(&buf).await.unwrap();
        assert_eq!(req.subsystem_name, "sftp");
    }

    // -------------------------------------------------------------------
    // Test 12: handle_request exit-status dispatch
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exit_status() {
        let (server_writer, _client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request_data = encode_exit_status_data(0).await.unwrap();
        let event = ChannelEvent::Request {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, None, "exit-status should return None (server→client)");
    }

    // -------------------------------------------------------------------
    // Test 13: handle_request exit-signal dispatch
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exit_signal() {
        let (server_writer, _client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request_data =
            encode_exit_signal_data("KILL", true, "killed", "en").await.unwrap();
        let event = ChannelEvent::Request {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, None, "exit-signal should return None (server→client)");
    }

    // -------------------------------------------------------------------
    // Test 14: shell request starts and exits
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn shell_request_starts() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        // Shell with no stdin will immediately hit EOF and exit.
        let (_, rx) = mpsc::channel(1);
        run_shell(default_shell(), &mut server_writer, rx, None).await.unwrap();
        drop(server_writer);

        // Should eventually get exit-status, EOF, Close
        let mut found_exit_status = false;
        let mut found_eof = false;
        let mut found_close = false;
        loop {
            let msg = match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => msg,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected error: {e}"),
            };
            match &msg {
                SshMessage::ChannelRequest { request_type, .. } if request_type == "exit-status" => {
                    found_exit_status = true;
                }
                SshMessage::ChannelEof => found_eof = true,
                SshMessage::ChannelClose => found_close = true,
                _ => {} // ignore other messages (e.g., data)
            }
        }
        assert!(found_exit_status, "should have received exit-status");
        assert!(found_eof, "should have received ChannelEof");
        assert!(found_close, "should have received ChannelClose");
    }

    // -------------------------------------------------------------------
    // Test 15: exec stderr output → ChannelExtendedData
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_stderr_output() {
        let (server_writer, mut client_reader) = duplex(65536);
        let mut server_writer = server_writer;

        let (_, rx) = mpsc::channel(1);
        run_exec("echo stderr_msg >&2", &mut server_writer, rx, None)
            .await
            .unwrap();
        drop(server_writer);

        // Collect all messages
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // Find ChannelExtendedData with stderr
        let has_stderr = messages.iter().any(|m| match m {
            SshMessage::ChannelExtendedData { data_type, data } => {
                *data_type == 1 && String::from_utf8_lossy(data).contains("stderr_msg")
            }
            _ => false,
        });
        assert!(has_stderr, "expected ChannelExtendedData with stderr_msg, got: {messages:?}");
    }
}
