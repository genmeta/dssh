//! Process spawning and I/O relay for SSH3 session channels.
//!
//! Provides two execution modes:
//! - **Piped**: stdin/stdout/stderr are separate pipes; stdout → channel data,
//!   stderr → channel extended data (type 1).
//! - **PTY**: all I/O through a PTY master; everything → channel data.
//!
//! Both modes use `tokio::select!` for output multiplexing (no intermediate
//! mpsc channels) and a spawned task for input relay (channel → process).

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

use h3x::varint::VarInt;
use nix::unistd::{Pid, setpgid};
use snafu::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{SshBool, SshBytes, SshString};
use crate::conversation::{
    ChannelEvent, SendChannelNoticeError, WriteChannelCloseError,
    WriteChannelDataError, WriteChannelEofError, WriteChannelExtendedDataError,
    read_channel_event, send_channel_notice, write_channel_close, write_channel_data,
    write_channel_eof, write_channel_extended_data,
};
use crate::session::pty::PtyPair;
use crate::session::signal;
use crate::session::{
    ExitSignalChannelNotice, ExitSignalRequest, ExitStatusChannelNotice, ExitStatusRequest,
    SessionCodecError, SignalRequest, WindowChangeRequest,
};

// ============================================================================
// Error types
// ============================================================================

/// Error from [`run_piped`] or [`run_pty`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ProcessError {
    #[snafu(display("failed to spawn command"))]
    Spawn { source: std::io::Error },

    #[snafu(display("failed to read from process stdout"))]
    ReadStdout { source: std::io::Error },

    #[snafu(display("failed to read from process stderr"))]
    ReadStderr { source: std::io::Error },

    #[snafu(display("failed to read from PTY master"))]
    ReadPty { source: std::io::Error },

    #[snafu(display("failed to write channel data"))]
    WriteData { source: WriteChannelDataError },

    #[snafu(display("failed to write channel extended data"))]
    WriteExtendedData { source: WriteChannelExtendedDataError },

    #[snafu(display("failed to send exit notification"))]
    SendExit { source: SendChannelNoticeError<SessionCodecError> },

    #[snafu(display("failed to write channel EOF"))]
    WriteEof { source: WriteChannelEofError },

    #[snafu(display("failed to write channel close"))]
    WriteClose { source: WriteChannelCloseError },

    #[snafu(display("failed to wait for child process"))]
    Wait { source: std::io::Error },

    #[snafu(display("failed to shutdown channel writer"))]
    Shutdown { source: std::io::Error },
}

// ============================================================================
// Configuration
// ============================================================================

/// How to spawn the command.
pub enum CommandMode<'a> {
    /// Execute `shell -c <command>`.
    Exec {
        shell: &'a OsStr,
        command: &'a [u8],
    },
    /// Launch an interactive shell (no args).
    Shell { shell: &'a OsStr },
}

impl<'a> CommandMode<'a> {
    fn program(&self) -> &OsStr {
        match self {
            Self::Exec { shell, .. } | Self::Shell { shell } => shell,
        }
    }

    fn args(&self) -> Vec<OsString> {
        match self {
            Self::Exec { command, .. } => {
                vec![OsString::from("-c"), OsString::from_vec(command.to_vec())]
            }
            Self::Shell { .. } => vec![],
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Run a command with piped stdio (no PTY).
///
/// - Channel data → process stdin
/// - Process stdout → channel data
/// - Process stderr → channel extended data (type 1)
/// - Channel signal requests → delivered to process group
///
/// On completion, sends exit-status/exit-signal + EOF + Close.
pub async fn run_piped<R, W>(
    channel_reader: R,
    channel_writer: &mut W,
    mode: CommandMode<'_>,
) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let mut cmd = tokio::process::Command::new(mode.program());
    cmd.args(mode.args())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // New process group for clean signal delivery.
    unsafe {
        cmd.pre_exec(|| {
            setpgid(Pid::from_raw(0), Pid::from_raw(0)).map_err(std::io::Error::other)
        });
    }

    let mut child = cmd.spawn().context(SpawnSnafu)?;
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let pid = child.id().map(|id| Pid::from_raw(id as i32));

    // Input relay: channel → process stdin + signal handling.
    // Runs in a spawned task because read_channel_event is not cancellation-safe.
    let input_handle = tokio::spawn(relay_input_piped(channel_reader, stdin, pid));

    // Output relay: stdout/stderr → channel (in main task, using select!).
    relay_output_piped(&mut stdout, &mut stderr, channel_writer).await?;

    // Wait for child exit.
    let status = child.wait().await.context(WaitSnafu)?;

    // Send exit notification.
    send_exit_notification(channel_writer, &status).await?;

    // Send EOF + Close + shutdown.
    write_channel_eof(channel_writer).await.context(WriteEofSnafu)?;
    write_channel_close(channel_writer).await.context(WriteCloseSnafu)?;
    channel_writer.shutdown().await.context(ShutdownSnafu)?;

    // Clean up input relay.
    input_handle.abort();
    let _ = input_handle.await;

    Ok(())
}

/// Run a command with a PTY.
///
/// - Channel data → PTY master (stdin)
/// - PTY master (stdout+stderr combined) → channel data
/// - Channel signal requests → delivered to process group
/// - Channel window-change requests → resize PTY
///
/// On completion, sends exit-status/exit-signal + EOF + Close.
pub async fn run_pty<R, W>(
    channel_reader: R,
    channel_writer: &mut W,
    mode: CommandMode<'_>,
    pty: PtyPair,
) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    // Set up child process with PTY slave as stdio.
    let slave_fd = pty.slave.into_raw_fd();
    let stdout_fd = nix::unistd::dup(slave_fd).map_err(std::io::Error::other).context(SpawnSnafu)?;
    let stderr_fd = nix::unistd::dup(slave_fd).map_err(std::io::Error::other).context(SpawnSnafu)?;

    let mut child = tokio::process::Command::new(mode.program())
        .args(mode.args())
        .stdin(unsafe { Stdio::from_raw_fd(slave_fd) })
        .stdout(unsafe { Stdio::from_raw_fd(stdout_fd) })
        .stderr(unsafe { Stdio::from_raw_fd(stderr_fd) })
        .spawn()
        .context(SpawnSnafu)?;

    let pid = child.id().map(|id| Pid::from_raw(id as i32));

    // Wrap PTY master in async file, then split for concurrent read/write.
    let master_file = std::fs::File::from(pty.master);
    let master_tokio = tokio::fs::File::from(master_file);
    let (mut master_reader, master_writer) = tokio::io::split(master_tokio);

    // Input relay: channel → PTY master + signal/window-change handling.
    let input_handle = tokio::spawn(relay_input_pty(channel_reader, master_writer, pid));

    // Output relay: PTY master → channel data.
    // EIO is expected when the child exits (slave side closes).
    let output_result = relay_output_pty(&mut master_reader, channel_writer).await;
    if let Err(ProcessError::ReadPty { ref source }) = output_result {
        if source.raw_os_error() != Some(nix::libc::EIO) {
            output_result?;
        }
    }

    // Wait for child exit.
    let status = child.wait().await.context(WaitSnafu)?;

    // Send exit notification.
    send_exit_notification(channel_writer, &status).await?;

    // Send EOF + Close + shutdown.
    write_channel_eof(channel_writer).await.context(WriteEofSnafu)?;
    write_channel_close(channel_writer).await.context(WriteCloseSnafu)?;
    channel_writer.shutdown().await.context(ShutdownSnafu)?;

    // Clean up input relay.
    input_handle.abort();
    let _ = input_handle.await;

    Ok(())
}

// ============================================================================
// Output relay
// ============================================================================

/// Multiplex stdout and stderr to the channel writer using `tokio::select!`.
async fn relay_output_piped<W>(
    stdout: &mut (impl AsyncRead + Unpin),
    stderr: &mut (impl AsyncRead + Unpin),
    writer: &mut W,
) -> Result<(), ProcessError>
where
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let mut stdout_buf = [0u8; 8192];
    let mut stderr_buf = [0u8; 8192];
    let mut stdout_done = false;
    let mut stderr_done = false;

    while !stdout_done || !stderr_done {
        tokio::select! {
            result = stdout.read(&mut stdout_buf), if !stdout_done => {
                let n = result.context(ReadStdoutSnafu)?;
                if n == 0 {
                    stdout_done = true;
                    continue;
                }
                write_channel_data(
                    writer,
                    SshBytes::from(stdout_buf[..n].to_vec()),
                )
                .await
                .context(WriteDataSnafu)?;
            }
            result = stderr.read(&mut stderr_buf), if !stderr_done => {
                let n = result.context(ReadStderrSnafu)?;
                if n == 0 {
                    stderr_done = true;
                    continue;
                }
                write_channel_extended_data(
                    writer,
                    VarInt::from(1u8), // SSH_EXTENDED_DATA_STDERR
                    SshBytes::from(stderr_buf[..n].to_vec()),
                )
                .await
                .context(WriteExtendedDataSnafu)?;
            }
        }
    }

    Ok(())
}

/// Relay PTY master output to the channel writer.
async fn relay_output_pty<W>(
    master: &mut (impl AsyncRead + Unpin),
    writer: &mut W,
) -> Result<(), ProcessError>
where
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let mut buf = [0u8; 8192];
    loop {
        let n = master.read(&mut buf).await.context(ReadPtySnafu)?;
        if n == 0 {
            break;
        }
        write_channel_data(writer, SshBytes::from(buf[..n].to_vec()))
            .await
            .context(WriteDataSnafu)?;
    }
    Ok(())
}

// ============================================================================
// Input relay
// ============================================================================

/// Read from channel, write data to process stdin, deliver signals.
async fn relay_input_piped<R>(
    mut channel_reader: R,
    mut stdin: impl AsyncWrite + Unpin + Send,
    pid: Option<Pid>,
) where
    R: AsyncRead + Unpin + Send,
{
    loop {
        let event = match read_channel_event(&mut channel_reader).await {
            Ok(e) => e,
            Err(_) => break,
        };
        match event {
            ChannelEvent::Data(data) => {
                if stdin.write_all(data.as_ref().as_ref()).await.is_err() {
                    break;
                }
            }
            ChannelEvent::Request(incoming) => {
                if !handle_piped_request(incoming, pid).await {
                    break;
                }
            }
            ChannelEvent::Eof | ChannelEvent::Close => break,
            _ => {}
        }
    }
    // Drop stdin to signal EOF to child process.
}

/// Read from channel, write data to PTY master, deliver signals, handle
/// window-change requests.
async fn relay_input_pty<R>(
    mut channel_reader: R,
    mut pty_writer: impl AsyncWrite + Unpin + Send,
    pid: Option<Pid>,
) where
    R: AsyncRead + Unpin + Send,
{
    loop {
        let event = match read_channel_event(&mut channel_reader).await {
            Ok(e) => e,
            Err(_) => break,
        };
        match event {
            ChannelEvent::Data(data) => {
                if pty_writer.write_all(data.as_ref().as_ref()).await.is_err() {
                    break;
                }
            }
            ChannelEvent::Request(incoming) => {
                if !handle_pty_request(incoming, pid).await {
                    break;
                }
            }
            ChannelEvent::Eof | ChannelEvent::Close => break,
            _ => {}
        }
    }
    drop(pty_writer);
}

// ============================================================================
// Request handlers for input relay
// ============================================================================

/// Handle a channel request in piped mode. Returns `true` to continue, `false` to stop.
async fn handle_piped_request<R: AsyncRead + Unpin + Send>(
    incoming: crate::conversation::IncomingChannelRequest<'_, R>,
    pid: Option<Pid>,
) -> bool {
    match &**incoming.request_type() {
        "signal" => {
            let Ok((req, _responder)) = incoming.decode_payload::<SignalRequest, SessionCodecError>().await else {
                return false;
            };
            deliver_to_pid(pid, &req.signal_name);
            true
        }
        _ => {
            // Unknown request in piped mode — can't decode payload, abandon input.
            false
        }
    }
}

/// Handle a channel request in PTY mode. Returns `true` to continue, `false` to stop.
async fn handle_pty_request<R: AsyncRead + Unpin + Send>(
    incoming: crate::conversation::IncomingChannelRequest<'_, R>,
    pid: Option<Pid>,
) -> bool {
    match &**incoming.request_type() {
        "signal" => {
            let Ok((req, _responder)) = incoming.decode_payload::<SignalRequest, SessionCodecError>().await else {
                return false;
            };
            deliver_to_pid(pid, &req.signal_name);
            true
        }
        "window-change" => {
            let Ok((_req, _responder)) = incoming.decode_payload::<WindowChangeRequest, SessionCodecError>().await else {
                return false;
            };
            // Window-change requires the PTY master fd, which the input relay
            // doesn't own. The caller should handle this via a channel or by
            // restructuring. For now, we log and continue.
            // TODO: wire up PTY master fd for window-change
            true
        }
        _ => {
            // Unknown request — can't decode payload, abandon input.
            false
        }
    }
}

fn deliver_to_pid(pid: Option<Pid>, signal_name: &SshString) {
    let Some(pid) = pid else { return };
    let Some(sig) = signal::from_ssh_name(signal_name) else { return };
    if let Err(e) = signal::deliver(pid, sig) {
        tracing::warn!(
            error = %e,
            signal = %signal_name,
            pid = pid.as_raw(),
            "failed to deliver signal"
        );
    }
}

// ============================================================================
// Exit status notification
// ============================================================================

async fn send_exit_notification<W>(
    writer: &mut W,
    status: &std::process::ExitStatus,
) -> Result<(), ProcessError>
where
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    if let Some(signal_number) = status.signal() {
        let signal_name = signal::to_ssh_name(signal_number)
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(format!("signal-{signal_number}@genmeta-ssh3")));

        send_channel_notice(
            writer,
            &ExitSignalChannelNotice {
                payload: ExitSignalRequest {
                    signal_name: SshString::from(signal_name.into_owned()),
                    core_dumped: SshBool(status.core_dumped()),
                    error_message: SshString::from(""),
                    language_tag: SshString::from(""),
                },
            },
        )
        .await
        .context(SendExitSnafu)?;
    } else {
        let code = status.code().unwrap_or(255) as u32;
        send_channel_notice(
            writer,
            &ExitStatusChannelNotice {
                payload: ExitStatusRequest {
                    exit_status: VarInt::from(code),
                },
            },
        )
        .await
        .context(SendExitSnafu)?;
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::read_channel_event;

    // Helper: create a mock channel pair (in-memory duplex).
    fn channel_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        tokio::io::duplex(64 * 1024)
    }

    #[tokio::test]
    async fn run_piped_echo() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (mut client_reader, _client_writer) = tokio::io::split(client_stream);

        let handle = tokio::spawn(async move {
            run_piped(
                server_reader,
                &mut server_writer,
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"echo hello",
                },
            )
            .await
        });

        let mut all_data = Vec::new();
        loop {
            let event = read_channel_event(&mut client_reader).await;
            match event {
                Ok(ChannelEvent::Data(data)) => {
                    all_data.extend_from_slice(data.as_ref().as_ref());
                }
                Ok(ChannelEvent::Request(incoming)) => {
                    if &**incoming.request_type() == "exit-status" {
                        let _ = incoming.decode_payload::<ExitStatusRequest, SessionCodecError>().await;
                    } else if &**incoming.request_type() == "exit-signal" {
                        let _ = incoming.decode_payload::<ExitSignalRequest, SessionCodecError>().await;
                    }
                }
                Ok(ChannelEvent::Eof) => {}
                Ok(ChannelEvent::Close) => break,
                Err(_) => break,
                _ => {}
            }
        }

        assert_eq!(String::from_utf8_lossy(&all_data), "hello\n");
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_piped_stderr() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (mut client_reader, _client_writer) = tokio::io::split(client_stream);

        let handle = tokio::spawn(async move {
            run_piped(
                server_reader,
                &mut server_writer,
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"echo err >&2",
                },
            )
            .await
        });

        let mut stderr_data = Vec::new();
        loop {
            match read_channel_event(&mut client_reader).await {
                Ok(ChannelEvent::ExtendedData { data_type, data }) => {
                    assert_eq!(data_type, VarInt::from(1u8));
                    stderr_data.extend_from_slice(data.as_ref().as_ref());
                }
                Ok(ChannelEvent::Request(incoming)) => {
                    if &**incoming.request_type() == "exit-status" {
                        let _ = incoming.decode_payload::<ExitStatusRequest, SessionCodecError>().await;
                    } else if &**incoming.request_type() == "exit-signal" {
                        let _ = incoming.decode_payload::<ExitSignalRequest, SessionCodecError>().await;
                    }
                }
                Ok(ChannelEvent::Eof) => {}
                Ok(ChannelEvent::Close) => break,
                Err(_) => break,
                _ => {}
            }
        }

        assert_eq!(String::from_utf8_lossy(&stderr_data), "err\n");
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_piped_exit_code() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, mut server_writer) = tokio::io::split(server_stream);
        let (mut client_reader, _client_writer) = tokio::io::split(client_stream);

        let handle = tokio::spawn(async move {
            run_piped(
                server_reader,
                &mut server_writer,
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"exit 42",
                },
            )
            .await
        });

        let mut exit_code = None;
        loop {
            match read_channel_event(&mut client_reader).await {
                Ok(ChannelEvent::Request(incoming)) => {
                    if &**incoming.request_type() == "exit-status" {
                        let (req, _) = incoming
                            .decode_payload::<ExitStatusRequest, SessionCodecError>()
                            .await
                            .unwrap();
                        exit_code = Some(req.exit_status.into_inner() as u32);
                    } else if &**incoming.request_type() == "exit-signal" {
                        let _ = incoming.decode_payload::<ExitSignalRequest, SessionCodecError>().await;
                    }
                }
                Ok(ChannelEvent::Close) => break,
                Err(_) => break,
                _ => {}
            }
        }

        assert_eq!(exit_code, Some(42));
        handle.await.unwrap().unwrap();
    }
}
