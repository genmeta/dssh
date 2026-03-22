//! SSH3 session-layer request handling for exec, shell, subsystem, exit-status,
//! and exit-signal.
//!
//! Processes `ChannelMessage::Request` payloads dispatched from the channel
//! message loop. Supports:
//!
//! - `exec` — run a command via `/bin/sh -c`
//! - `shell` — launch an interactive shell
//! - `subsystem` — rejected (not implemented)
//! - `exit-status` — process exit code (server→client direction)
//! - `exit-signal` — process killed by signal (server→client direction)

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

use genmeta_ssh::{
    ChannelMessage, ChannelRequest, ExitSignalRequest, ExitStatusRequest,
    SignalRequest, SshBool, SshMessage, SshString,
};
use genmeta_ssh::codec::SshBytes;
use h3x::{
    codec::EncodeExt,
    varint::VarInt,
};
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::{Pid, dup, setpgid},
};
use snafu::Report;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::session::pty::{PtyPair, set_window_size};

#[cfg(test)]
fn default_shell() -> &'static OsStr {
    OsStr::new("/bin/sh")
}

// ---------------------------------------------------------------------------
// Exec/Shell/Subsystem handlers
// ---------------------------------------------------------------------------

/// Spawn `<shell> -c <command>`, copy stdout → ChannelData, stderr →
/// ChannelExtendedData, then send exit-status + EOF + Close.
///
/// When `pty` is `Some`, the child process uses the PTY slave as stdin/stdout/stderr,
/// and the PTY master is used for I/O relay.
pub async fn run_exec<W>(
    shell_path: &OsStr,
    command: &[u8],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelMessage>,
    pty: Option<PtyPair>,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let command = OsString::from_vec(command.to_vec());
    if let Some(pty_pair) = pty {
        run_command_with_pty(
            shell_path,
            &[OsString::from("-c"), command],
            writer,
            event_rx,
            pty_pair,
        )
        .await
    } else {
        run_command_piped(
            shell_path,
            &[OsString::from("-c"), command],
            writer,
            event_rx,
        )
        .await
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
    event_rx: mpsc::Receiver<ChannelMessage>,
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
    args: &[OsString],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelMessage>,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            setpgid(Pid::from_raw(0), Pid::from_raw(0)).map_err(io::Error::other)
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            tracing::error!(error = %Report::from_error(&e), "failed to spawn command");
            writer.encode_one(SshMessage::Channel(ChannelMessage::Failure)).await.map_err(io::Error::other)?;
            return Err(e);
        }
    };

    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdin = child.stdin.take().unwrap();
    let child_pid = child.id().unwrap_or(0) as i32;

    // Spawn a stdin relay task: reads ChannelMessage::Data from event_rx -> writes to stdin.
    let stdin_task = tokio::spawn(async move {
        let mut stdin = stdin;
        let mut event_rx = event_rx;
        while let Some(event) = event_rx.recv().await {
            match event {
                ChannelMessage::Data(data)
                    if stdin.write_all(data.as_ref().as_ref()).await.is_err() =>
                {
                    break;
                }
                ChannelMessage::Request(ChannelRequest::Signal { request, .. }) => {
                    if let Err(error) = deliver_signal(child_pid, &request) {
                        tracing::warn!(error = %Report::from_error(&error), child_pid, "failed to deliver signal to non-PTY child");
                    }
                }
                ChannelMessage::Eof => break,
                _ => {}
            }
        }
        drop(stdin); // Close stdin to signal EOF to child
    }.in_current_span());

    copy_command_output(stdout, stderr, writer).await?;

    // Wait for process to exit.
    let status = child.wait().await?;
    if let Some(signal_number) = status.signal() {
        let signal_name = exit_signal_name(signal_number);
        writer.encode_one(SshMessage::Channel(ChannelMessage::Request(
            ChannelRequest::ExitSignal(ExitSignalRequest {
                signal_name: SshString::from(signal_name.into_owned()),
                core_dumped: SshBool(status.core_dumped()),
                error_message: SshString::from(""),
                language_tag: SshString::from(""),
            })
        ))).await.map_err(io::Error::other)?;
    } else {
        let exit_code = status.code().unwrap_or(255) as u32;
        writer.encode_one(SshMessage::Channel(ChannelMessage::Request(
            ChannelRequest::ExitStatus(ExitStatusRequest {
                exit_status: VarInt::from(exit_code),
            })
        ))).await.map_err(io::Error::other)?;
    }

    // Send EOF + Close.
    writer.encode_one(SshMessage::Channel(ChannelMessage::Eof)).await.map_err(io::Error::other)?;
    writer.encode_one(SshMessage::Channel(ChannelMessage::Close)).await.map_err(io::Error::other)?;
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
    args: &[OsString],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelMessage>,
    pty_pair: PtyPair,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    // Duplicate the slave fd for stdout and stderr before consuming for stdin.
    let slave_raw = pty_pair.slave.as_raw_fd();
    let stdout_fd = dup(slave_raw).map_err(io::Error::other)?;
    let stderr_fd = dup(slave_raw).map_err(io::Error::other)?;
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
            writer.encode_one(SshMessage::Channel(ChannelMessage::Failure)).await.map_err(io::Error::other)?;
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

    // Spawn stdin relay task: reads ChannelMessage::Data -> writes to PTY master,
    // handles Signal and WindowChange events.
    let stdin_task = tokio::spawn(async move {
        let mut master_writer = master_writer;
        let mut event_rx = event_rx;
        while let Some(event) = event_rx.recv().await {
            match event {
                ChannelMessage::Data(data)
                    if master_writer.write_all(data.as_ref().as_ref()).await.is_err() =>
                {
                    break;
                }
                ChannelMessage::Request(request) => {
                    match request {
                        ChannelRequest::Signal { request, .. } => {
                            if let Err(error) = deliver_signal(child_pid, &request) {
                                tracing::warn!(error = %Report::from_error(&error), child_pid, "failed to deliver signal to PTY child");
                            }
                        }
                        ChannelRequest::WindowChange(req) => {
                            if let Err(error) = set_window_size(master_raw_fd, &req) {
                                tracing::warn!(
                                    error = %Report::from_error(&error),
                                    width_cols = %req.width_cols,
                                    height_rows = %req.height_rows,
                                    "window-change resize failed, keeping current size"
                                );
                            }
                        }
                        _ => {}
                    }
                }
                ChannelMessage::Eof => break,
                _ => {}
            }
        }
        drop(master_writer);
    }.in_current_span());

    // Read from PTY master → ChannelData (PTY combines stdout+stderr).
    let stdout_result = copy_command_output_from_reader(&mut master_reader, writer).await;

    // EIO is expected when the child exits and the slave side closes.
    if let Err(ref e) = stdout_result
        && e.raw_os_error() != Some(libc::EIO)
    {
        stdout_result?;
    }

    // Wait for process to exit — use the same signal-aware split as non-PTY.
    let status = child.wait().await?;
    if let Some(signal_number) = status.signal() {
        let signal_name = exit_signal_name(signal_number);
        writer.encode_one(SshMessage::Channel(ChannelMessage::Request(
            ChannelRequest::ExitSignal(ExitSignalRequest {
                signal_name: SshString::from(signal_name.into_owned()),
                core_dumped: SshBool(status.core_dumped()),
                error_message: SshString::from(""),
                language_tag: SshString::from(""),
            })
        ))).await.map_err(io::Error::other)?;
    } else {
        let exit_code = status.code().unwrap_or(255) as u32;
        writer.encode_one(SshMessage::Channel(ChannelMessage::Request(
            ChannelRequest::ExitStatus(ExitStatusRequest {
                exit_status: VarInt::from(exit_code),
            })
        ))).await.map_err(io::Error::other)?;
    }

    // Send EOF + Close.
    writer.encode_one(SshMessage::Channel(ChannelMessage::Eof)).await.map_err(io::Error::other)?;
    writer.encode_one(SshMessage::Channel(ChannelMessage::Close)).await.map_err(io::Error::other)?;
    writer.shutdown().await?;

    // Clean up stdin relay task.
    stdin_task.abort();
    let _ = stdin_task.await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

enum CommandOutputChunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

async fn copy_command_output<Stdout, Stderr, W>(
    stdout: Stdout,
    stderr: Stderr,
    writer: &mut W,
) -> io::Result<()>
where
    Stdout: AsyncRead + Send + Unpin + 'static,
    Stderr: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin,
{
    let (tx, mut rx) = mpsc::channel(8);
    let stdout_task = tokio::spawn(read_stream_chunks(stdout, tx.clone(), true).in_current_span());
    let stderr_task = tokio::spawn(read_stream_chunks(stderr, tx, false).in_current_span());

    while let Some(chunk) = rx.recv().await {
        match chunk {
            CommandOutputChunk::Stdout(data) => {
                writer.encode_one(SshMessage::Channel(ChannelMessage::Data(SshBytes::from(data)))).await.map_err(io::Error::other)?;
            }
            CommandOutputChunk::Stderr(data) => {
                writer
                    .encode_one(SshMessage::Channel(ChannelMessage::ExtendedData {
                        data_type: VarInt::from(1u8),
                        data: SshBytes::from(data),
                    }))
                    .await.map_err(io::Error::other)?;
            }
        }
    }

    stdout_task.await.map_err(io::Error::other)??;
    stderr_task.await.map_err(io::Error::other)??;
    Ok(())
}

async fn read_stream_chunks<R>(
    mut reader: R,
    tx: mpsc::Sender<CommandOutputChunk>,
    is_stdout: bool,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin,
{
    let mut buf = vec![0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let chunk = if is_stdout {
            CommandOutputChunk::Stdout(buf[..n].to_vec())
        } else {
            CommandOutputChunk::Stderr(buf[..n].to_vec())
        };
        if tx.send(chunk).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn copy_command_output_from_reader<R, W>(reader: &mut R, writer: &mut W) -> io::Result<()>
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
        writer
            .encode_one(SshMessage::Channel(ChannelMessage::Data(
                SshBytes::from(buf[..n].to_vec()),
            )))
            .await.map_err(io::Error::other)?;
    }
    Ok(())
}

fn signal_number(signal_name: &str) -> Option<Signal> {
    match signal_name {
        "HUP" => Some(Signal::SIGHUP),
        "INT" => Some(Signal::SIGINT),
        "QUIT" => Some(Signal::SIGQUIT),
        "KILL" => Some(Signal::SIGKILL),
        "TERM" => Some(Signal::SIGTERM),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        _ => None,
    }
}

fn signal_number_name(signal_number: i32) -> Option<&'static str> {
    match signal_number {
        libc::SIGABRT => Some("ABRT"),
        libc::SIGALRM => Some("ALRM"),
        libc::SIGFPE => Some("FPE"),
        libc::SIGHUP => Some("HUP"),
        libc::SIGILL => Some("ILL"),
        libc::SIGINT => Some("INT"),
        libc::SIGQUIT => Some("QUIT"),
        libc::SIGKILL => Some("KILL"),
        libc::SIGPIPE => Some("PIPE"),
        libc::SIGSEGV => Some("SEGV"),
        libc::SIGTERM => Some("TERM"),
        libc::SIGUSR1 => Some("USR1"),
        libc::SIGUSR2 => Some("USR2"),
        _ => None,
    }
}

fn exit_signal_name(signal_number: i32) -> Cow<'static, str> {
    signal_number_name(signal_number)
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(format!("signal-{signal_number}@genmeta-ssh3")))
}

fn deliver_signal(child_pid: i32, req: &SignalRequest) -> io::Result<()> {
    if child_pid <= 0 {
        return Ok(());
    }

    let Some(sig) = signal_number(&req.signal_name) else {
        return Ok(());
    };

    let child_pid = Pid::from_raw(child_pid);
    match signal::killpg(child_pid, sig) {
        Ok(()) => Ok(()),
        Err(Errno::ESRCH) => signal::kill(child_pid, sig).map_err(io::Error::other),
        Err(error) => Err(io::Error::other(error)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh::{
        ChannelMessage,
        ChannelRequest,
        ExecRequest,
        PtyRequest,
        RequestAction,
        SshBool,
        SshString,
        SubsystemRequest,
        channel::UnknownBody,
        codec::{MAX_REMOTE_FIELD_SIZE, SshBytes},
        handle_request,
        message::SshMessage,
        session::encode_exit_status,
    };
    use h3x::codec::{DecodeFrom, EncodeExt, EncodeInto};
    use tokio::io::duplex;

    async fn encode_request_data<T, E>(item: T) -> Result<Vec<u8>, E>
    where
        for<'a> T: EncodeInto<&'a mut Vec<u8>, Output = (), Error = E>,
    {
        let mut buf = Vec::new();
        buf.encode_one(item).await?;
        Ok(buf)
    }

    /// Check if a decode error is caused by EOF (stream exhausted).
    fn is_eof_error(e: &impl std::fmt::Debug) -> bool {
        format!("{e:?}").contains("UnexpectedEof")
    }

    // -------------------------------------------------------------------
    // Test 1: exec request codec parses SshString payloads
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_codec_simple() {
        // Encode "echo hello" as SshString
        let (mut writer, mut reader) = duplex(4096);
        SshString::from("echo hello")
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let req = ExecRequest::decode_from(buf.as_slice()).await.unwrap();
        assert_eq!(req.command.as_ref().as_ref(), b"echo hello");
    }

    #[tokio::test]
    async fn exec_request_codec_empty() {
        // Encode empty string as SshString
        let (mut writer, mut reader) = duplex(4096);
        SshString::from("")
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let req = ExecRequest::decode_from(buf.as_slice()).await.unwrap();
        assert_eq!(req.command.as_ref().as_ref(), b"");
    }

    #[tokio::test]
    async fn exec_request_codec_non_utf8() {
        let request_data = vec![0x03, 0x66, 0x6f, 0xff];

        let req = ExecRequest::decode_from(request_data.as_slice()).await.unwrap();
        assert_eq!(req.command.as_ref().as_ref(), &[0x66, 0x6f, 0xff]);
    }

    #[tokio::test]
    async fn exec_request_rejects_oversized_command() {
        let mut request_data = Vec::new();
        request_data
            .encode_one(VarInt::try_from((MAX_REMOTE_FIELD_SIZE + 1) as u64).unwrap())
            .await
            .unwrap();

        let err = ExecRequest::decode_from(request_data.as_slice())
            .await
            .unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("exec command length") || err_str.contains("field length") || err_str.contains("too large") || err_str.contains("session codec"),
            "expected error about oversized command, got: {err_str}"
        );
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
        run_exec(default_shell(), b"echo hello", &mut server_writer, rx, None)
            .await
            .unwrap();
        drop(server_writer);

        // Collect all messages sent to the client.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if is_eof_error(&e) => break,
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
            SshMessage::Channel(ChannelMessage::Data(data)) => {
                String::from_utf8_lossy(data.as_ref().as_ref()).contains("hello")
            }
            _ => false,
        });
        assert!(
            has_hello,
            "expected ChannelData containing 'hello', got: {messages:?}"
        );

        // Check exit-status request
        let has_exit_status = messages.iter().any(|m| matches!(
            m,
            SshMessage::Channel(ChannelMessage::Request(
                ChannelRequest::ExitStatus(req)
            )) if req.exit_status == VarInt::from(0u32)
        ));
        assert!(
            has_exit_status,
            "expected exit-status request with code 0, got: {messages:?}"
        );

        // Check EOF and Close are present
        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::Channel(ChannelMessage::Eof))),
            "expected ChannelEof"
        );
        assert!(
            messages
                .iter()
                .any(|m| matches!(m, SshMessage::Channel(ChannelMessage::Close))),
            "expected ChannelClose"
        );

        // Verify ordering: exit-status comes before EOF, EOF before Close
        let exit_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::Channel(ChannelMessage::Request(ChannelRequest::ExitStatus(_)))))
            .unwrap();
        let eof_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::Channel(ChannelMessage::Eof)))
            .unwrap();
        let close_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::Channel(ChannelMessage::Close)))
            .unwrap();
        assert!(exit_pos < eof_pos, "exit-status should come before EOF");
        assert!(eof_pos < close_pos, "EOF should come before Close");
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
        run_exec(
            default_shell(),
            b"__nonexistent_command_xyz_2024__",
            &mut server_writer,
            rx,
            None,
        )
        .await
        .unwrap();
        drop(server_writer);

        // Collect all messages.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // Should have exit-status with non-zero code, EOF, Close.
        let has_nonzero_exit = messages.iter().any(|m| matches!(
            m,
            SshMessage::Channel(ChannelMessage::Request(
                ChannelRequest::ExitStatus(req)
            )) if req.exit_status != VarInt::from(0u32)
        ));
        assert!(
            has_nonzero_exit,
            "expected exit-status with non-zero code, got: {messages:?}"
        );

        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::Channel(ChannelMessage::Eof))),
            "expected ChannelEof"
        );
        assert!(
            messages
                .iter()
                .any(|m| matches!(m, SshMessage::Channel(ChannelMessage::Close))),
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

        let request = ChannelRequest::Subsystem {
            want_reply: SshBool(true),
            request: SubsystemRequest {
                subsystem_name: SshString::from("sftp"),
            },
        };

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(result, None, "subsystem should return None");

        drop(server_writer);

        // Should have sent ChannelFailure.
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::Channel(ChannelMessage::Failure));
    }

    // -------------------------------------------------------------------
    // Test 6: handle_request dispatches exec correctly
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exec() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request = ChannelRequest::Exec {
            want_reply: SshBool(true),
            request: ExecRequest {
                command: SshBytes::from(b"ls -la".to_vec()),
            },
        };

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Exec(SshBytes::from(b"ls -la".to_vec()))));

        drop(server_writer);

        // Should have sent ChannelSuccess (want_reply=true).
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::Channel(ChannelMessage::Success));
    }

    #[tokio::test]
    async fn handle_request_shell() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request = ChannelRequest::Shell {
            want_reply: SshBool(true),
        };

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Shell));

        drop(server_writer);

        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::Channel(ChannelMessage::Success));
    }

    #[tokio::test]
    async fn handle_request_unknown_type() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request = ChannelRequest::Unknown {
            request_type: SshString::from("x11-req"),
            want_reply: SshBool(true),
            body: UnknownBody::Unavailable,
        };

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(result, None);

        drop(server_writer);

        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(msg, SshMessage::Channel(ChannelMessage::Failure));
    }

    #[tokio::test]
    async fn handle_request_no_reply() {
        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request = ChannelRequest::Shell {
            want_reply: SshBool(false),
        };

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Shell));

        drop(server_writer);

        // No reply should have been sent.
        let result = SshMessage::decode_from(&mut client_reader).await;
        assert!(
            result.is_err(),
            "no message should be sent when want_reply=false"
        );
    }

    // -------------------------------------------------------------------
    // Test 7: exit-status request codec roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_request_codec_roundtrip() {
        let data = encode_request_data(ExitStatusRequest { exit_status: VarInt::from(42u32) })
            .await
            .unwrap();
        let req = ExitStatusRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.exit_status, VarInt::from(42u32));
    }

    #[tokio::test]
    async fn exit_status_request_codec_zero() {
        let data = encode_request_data(ExitStatusRequest { exit_status: VarInt::from(0u32) })
            .await
            .unwrap();
        let req = ExitStatusRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.exit_status, VarInt::from(0u32));
    }

    #[tokio::test]
    async fn exit_status_request_codec_255() {
        let data = encode_request_data(ExitStatusRequest { exit_status: VarInt::from(255u32) })
            .await
            .unwrap();
        let req = ExitStatusRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.exit_status, VarInt::from(255u32));
    }

    // -------------------------------------------------------------------
    // Test 8: exit-signal request codec roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_signal_request_codec_roundtrip() {
        let data = encode_request_data(ExitSignalRequest {
            signal_name: SshString::from("KILL"),
            core_dumped: SshBool(true),
            error_message: SshString::from("killed by signal"),
            language_tag: SshString::from("en"),
        })
            .await
            .unwrap();
        let req = ExitSignalRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(&*req.signal_name, "KILL");
        assert!(req.core_dumped.0);
        assert_eq!(&*req.error_message, "killed by signal");
        assert_eq!(&*req.language_tag, "en");
    }

    #[tokio::test]
    async fn exit_signal_request_codec_no_core_dump() {
        let data = encode_request_data(ExitSignalRequest {
            signal_name: SshString::from("TERM"),
            core_dumped: SshBool(false),
            error_message: SshString::from("terminated"),
            language_tag: SshString::from(""),
        })
            .await
            .unwrap();
        let req = ExitSignalRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(&*req.signal_name, "TERM");
        assert!(!req.core_dumped.0);
        assert_eq!(&*req.error_message, "terminated");
        assert_eq!(&*req.language_tag, "");
    }

    // -------------------------------------------------------------------
    // Test 9: exit-status channel request encoding
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_channel_request_message() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Request(
            ChannelRequest::ExitStatus(ExitStatusRequest {
                exit_status: VarInt::from(42u32),
            })
        ))
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::Channel(ChannelMessage::Request(
                ChannelRequest::ExitStatus(req)
            )) => {
                assert_eq!(req.exit_status, VarInt::from(42u32));
            }
            other => panic!("expected exit-status ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 10: exit-signal channel request encoding
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_signal_channel_request_message() {
        let (mut writer, mut reader) = duplex(8192);
        SshMessage::Channel(ChannelMessage::Request(
            ChannelRequest::ExitSignal(ExitSignalRequest {
                signal_name: SshString::from("TERM"),
                core_dumped: SshBool(false),
                error_message: SshString::from("terminated"),
                language_tag: SshString::from("en"),
            })
        ))
        .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::Channel(ChannelMessage::Request(
                ChannelRequest::ExitSignal(req)
            )) => {
                assert_eq!(&*req.signal_name, "TERM");
                assert!(!req.core_dumped.0);
                assert_eq!(&*req.error_message, "terminated");
                assert_eq!(&*req.language_tag, "en");
            }
            other => panic!("expected exit-signal ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 11: subsystem request codec
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_subsystem_name() {
        let mut buf = Vec::new();
        SshString::from("sftp")
            .encode_into(&mut buf)
            .await
            .unwrap();
        let req = SubsystemRequest::decode_from(buf.as_slice()).await.unwrap();
        assert_eq!(&*req.subsystem_name, "sftp");
    }

    // -------------------------------------------------------------------
    // Test 12: handle_request exit-status dispatch
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exit_status() {
        let (server_writer, _client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request = ChannelRequest::ExitStatus(ExitStatusRequest {
            exit_status: VarInt::from(0u32),
        });

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(
            result, None,
            "exit-status should return None (server→client)"
        );
    }

    // -------------------------------------------------------------------
    // Test 13: handle_request exit-signal dispatch
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exit_signal() {
        let (server_writer, _client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request = ChannelRequest::ExitSignal(ExitSignalRequest {
            signal_name: SshString::from("KILL"),
            core_dumped: SshBool(true),
            error_message: SshString::from("killed"),
            language_tag: SshString::from("en"),
        });

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert_eq!(
            result, None,
            "exit-signal should return None (server→client)"
        );
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
        run_shell(default_shell(), &mut server_writer, rx, None)
            .await
            .unwrap();
        drop(server_writer);

        // Should eventually get exit-status, EOF, Close
        let mut found_exit_status = false;
        let mut found_eof = false;
        let mut found_close = false;
        loop {
            let msg = match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => msg,
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            };
            match &msg {
                SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitStatus(_)
                )) => {
                    found_exit_status = true;
                }
                SshMessage::Channel(ChannelMessage::Eof) => found_eof = true,
                SshMessage::Channel(ChannelMessage::Close) => found_close = true,
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
        run_exec(
            default_shell(),
            b"echo stderr_msg >&2",
            &mut server_writer,
            rx,
            None,
        )
        .await
        .unwrap();
        drop(server_writer);

        // Collect all messages
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // Find ChannelExtendedData with stderr
        let has_stderr = messages.iter().any(|m| match m {
            SshMessage::Channel(ChannelMessage::ExtendedData { data_type, data }) => {
                *data_type == VarInt::from(1u8)
                    && String::from_utf8_lossy(data.as_ref().as_ref()).contains("stderr_msg")
            }
            _ => false,
        });
        assert!(
            has_stderr,
            "expected ChannelExtendedData with stderr_msg, got: {messages:?}"
        );
    }

    #[tokio::test]
    async fn exec_large_stderr_streams_incrementally() {
        let (server_writer, mut client_reader) = duplex(262144);
        let mut server_writer = server_writer;

        let (_, rx) = mpsc::channel(1);
        run_exec(
            default_shell(),
            b"i=0; while [ $i -lt 20000 ]; do printf x >&2; i=$((i+1)); done",
            &mut server_writer,
            rx,
            None,
        )
        .await
        .unwrap();
        drop(server_writer);

        let mut stderr_frames = 0usize;
        let mut total_stderr = 0usize;
        let mut eof_pos = None;
        let mut close_pos = None;
        let mut exit_pos = None;
        let mut index = 0usize;

        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(SshMessage::Channel(ChannelMessage::ExtendedData { data_type, data })) => {
                    assert_eq!(data_type, VarInt::from(1u8));
                    stderr_frames += 1;
                    total_stderr += data.as_ref().len();
                    index += 1;
                }
                Ok(SshMessage::Channel(ChannelMessage::Request(ChannelRequest::ExitStatus(_)))) => {
                    exit_pos = Some(index);
                    index += 1;
                }
                Ok(SshMessage::Channel(ChannelMessage::Eof)) => {
                    eof_pos = Some(index);
                    index += 1;
                }
                Ok(SshMessage::Channel(ChannelMessage::Close)) => {
                    close_pos = Some(index);
                    index += 1;
                }
                Ok(_) => {
                    index += 1;
                }
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert!(stderr_frames > 1, "expected multiple stderr frames, got {stderr_frames}");
        assert_eq!(total_stderr, 20000);

        let exit_pos = exit_pos.expect("missing exit-status");
        let eof_pos = eof_pos.expect("missing eof");
        let close_pos = close_pos.expect("missing close");
        assert!(exit_pos < eof_pos, "exit-status should come before EOF");
        assert!(eof_pos < close_pos, "EOF should come before Close");
    }

    // -------------------------------------------------------------------
    // Test 16: PTY signal termination emits exit-signal, not exit-status
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pty_signal_emits_exit_signal_instead_of_exit_status() {
        use crate::session::pty::allocate_pty;
        use genmeta_ssh::PtyRequest;

        let pty_req = PtyRequest {
            term_type: SshString::from("xterm"),
            width_cols: VarInt::from(80u32),
            height_rows: VarInt::from(24u32),
            width_px: VarInt::from(0u32),
            height_px: VarInt::from(0u32),
            terminal_modes: SshBytes::from(vec![]),
        };
        let pty_pair = allocate_pty(&pty_req).expect("allocate_pty failed");

        let (server_writer, mut client_reader) = duplex(65536);
        let mut server_writer = server_writer;

        let (event_tx, rx) = mpsc::channel(8);
        let run_handle = tokio::spawn(async move {
            run_exec(
                default_shell(),
                b"exec sleep 30",
                &mut server_writer,
                rx,
                Some(pty_pair),
            )
            .await
            .unwrap();
            drop(server_writer);
        });

        // Give the child time to start.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Send TERM signal via channel event.
        event_tx
            .send(ChannelMessage::Request(ChannelRequest::Signal {
                want_reply: SshBool(false),
                request: SignalRequest {
                    signal_name: SshString::from("TERM"),
                },
            }))
            .await
            .unwrap();
        drop(event_tx);

        tokio::time::timeout(std::time::Duration::from_secs(5), run_handle)
            .await
            .expect("signaled PTY command should terminate promptly")
            .unwrap();

        let mut saw_exit_signal = false;
        let mut saw_exit_status = false;
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitSignal(req)
                ))) => {
                    assert_eq!(&*req.signal_name, "TERM");
                    assert_eq!(&*req.error_message, "");
                    assert_eq!(&*req.language_tag, "");
                    saw_exit_signal = true;
                }
                Ok(SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitStatus(_)
                ))) => {
                    saw_exit_status = true;
                }
                Ok(_) => {}
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert!(
            saw_exit_signal,
            "expected exit-signal after PTY signal termination"
        );
        assert!(
            !saw_exit_status,
            "PTY signal termination should not emit exit-status (no double-emission)"
        );
    }

    // -------------------------------------------------------------------
    // Test 17: PTY numeric exit still emits exit-status
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pty_numeric_exit_emits_exit_status() {
        use crate::session::pty::allocate_pty;
        use genmeta_ssh::PtyRequest;

        let pty_req = PtyRequest {
            term_type: SshString::from("xterm"),
            width_cols: VarInt::from(80u32),
            height_rows: VarInt::from(24u32),
            width_px: VarInt::from(0u32),
            height_px: VarInt::from(0u32),
            terminal_modes: SshBytes::from(vec![]),
        };
        let pty_pair = allocate_pty(&pty_req).expect("allocate_pty failed");

        let (server_writer, mut client_reader) = duplex(65536);
        let mut server_writer = server_writer;

        let (_, rx) = mpsc::channel(1);
        run_exec(
            default_shell(),
            b"exit 42",
            &mut server_writer,
            rx,
            Some(pty_pair),
        )
        .await
        .unwrap();
        drop(server_writer);

        let mut saw_exit_status = false;
        let mut saw_exit_signal = false;
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitStatus(req)
                ))) => {
                    assert_eq!(req.exit_status, VarInt::from(42u32));
                    saw_exit_status = true;
                }
                Ok(SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitSignal(_)
                ))) => {
                    saw_exit_signal = true;
                }
                Ok(_) => {}
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert!(saw_exit_status, "PTY numeric exit should emit exit-status");
        assert!(
            !saw_exit_signal,
            "PTY numeric exit should not emit exit-signal"
        );
    }

    // -------------------------------------------------------------------
    // Test 18: non-PTY signal emits exit-signal instead of exit-status
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn non_pty_signal_emits_exit_signal_instead_of_exit_status() {
        let (server_writer, mut client_reader) = duplex(65536);
        let mut server_writer = server_writer;

        let (event_tx, rx) = mpsc::channel(8);
        let run_handle = tokio::spawn(async move {
            run_exec(default_shell(), b"sleep 30", &mut server_writer, rx, None)
                .await
                .unwrap();
            drop(server_writer);
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        event_tx
            .send(ChannelMessage::Request(ChannelRequest::Signal {
                want_reply: SshBool(false),
                request: SignalRequest {
                    signal_name: SshString::from("TERM"),
                },
            }))
            .await
            .unwrap();
        drop(event_tx);

        tokio::time::timeout(std::time::Duration::from_secs(5), run_handle)
            .await
            .expect("signaled non-PTY command should terminate promptly")
            .unwrap();

        let mut saw_exit_signal = false;
        let mut saw_exit_status = false;
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitSignal(req)
                ))) => {
                    assert_eq!(&*req.signal_name, "TERM");
                    assert_eq!(&*req.error_message, "");
                    assert_eq!(&*req.language_tag, "");
                    saw_exit_signal = true;
                }
                Ok(SshMessage::Channel(ChannelMessage::Request(
                    ChannelRequest::ExitStatus(_)
                ))) => {
                    saw_exit_status = true;
                }
                Ok(_) => {}
                Err(e) if is_eof_error(&e) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        assert!(
            saw_exit_signal,
            "expected exit-signal after non-PTY signal termination"
        );
        assert!(
            !saw_exit_status,
            "non-PTY signal termination should not emit exit-status"
        );
    }

    #[test]
    fn exit_signal_name_maps_extended_rfc_signal_set() {
        assert_eq!(exit_signal_name(libc::SIGPIPE), "PIPE");
        assert_eq!(exit_signal_name(libc::SIGABRT), "ABRT");
        assert_eq!(exit_signal_name(libc::SIGSEGV), "SEGV");
    }

    #[test]
    fn exit_signal_name_preserves_unknown_signal_without_fabricating_term() {
        assert_eq!(exit_signal_name(9999), "signal-9999@genmeta-ssh3");
    }

    // -------------------------------------------------------------------
    // Test 19: pty-req with want_reply=true sends NO premature reply
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_pty_req_no_premature_reply() {
        let request = ChannelRequest::PtyReq {
            want_reply: SshBool(true),
            request: PtyRequest {
                term_type: SshString::from("xterm"),
                width_cols: VarInt::from(80u32),
                height_rows: VarInt::from(24u32),
                width_px: VarInt::from(0u32),
                height_px: VarInt::from(0u32),
                terminal_modes: SshBytes::from(vec![]),
            },
        };

        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let result = handle_request(request, &mut server_writer).await.unwrap();
        assert!(
            matches!(result, Some(RequestAction::AllocatePty(_, SshBool(true)))),
            "expected AllocatePty with want_reply=true, got {result:?}"
        );

        drop(server_writer);

        let read_result = SshMessage::decode_from(&mut client_reader).await;
        assert!(
            read_result.is_err(),
            "pty-req must NOT send premature ChannelSuccess; reply is deferred to caller"
        );
    }

    // -------------------------------------------------------------------
    // Test 20: pty-req returns want_reply=true in AllocatePty
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_pty_req_returns_want_reply() {
        let pty_request = PtyRequest {
            term_type: SshString::from("vt100"),
            width_cols: VarInt::from(80u32),
            height_rows: VarInt::from(24u32),
            width_px: VarInt::from(0u32),
            height_px: VarInt::from(0u32),
            terminal_modes: SshBytes::from(vec![]),
        };

        let request_true = ChannelRequest::PtyReq {
            want_reply: SshBool(true),
            request: pty_request.clone(),
        };
        let request_false = ChannelRequest::PtyReq {
            want_reply: SshBool(false),
            request: pty_request,
        };

        let (mut w1, _r1) = duplex(8192);
        let (mut w2, _r2) = duplex(8192);

        let result_true = handle_request(request_true, &mut w1).await.unwrap();
        let result_false = handle_request(request_false, &mut w2).await.unwrap();

        match result_true {
            Some(RequestAction::AllocatePty(_, wr)) => assert_eq!(wr, SshBool(true), "want_reply should be true"),
            other => panic!("expected AllocatePty, got {other:?}"),
        }
        match result_false {
            Some(RequestAction::AllocatePty(_, wr)) => assert_eq!(wr, SshBool(false), "want_reply should be false"),
            other => panic!("expected AllocatePty, got {other:?}"),
        }
    }
}
