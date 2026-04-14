//! Process spawning and I/O relay for SSH3 session channels.
//!
//! Provides two execution modes:
//! - **Piped**: stdin/stdout/stderr are separate pipes; stdout → channel data,
//!   stderr → channel extended data (type 1).
//! - **PTY**: all I/O through a PTY master; everything → channel data.
//!
//! Both modes use `tokio::join!` for concurrent I/O relay (no spawned tasks,
//! no cancellation issues). The reader half uses `SshChannelReader::next_event`
//! which is safe since it never needs to be cancelled.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, RawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

use h3x::varint::VarInt;
use nix::unistd::{Pid, setpgid};
use snafu::prelude::*;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{SshBool, SshString};
use crate::conversation::channel::{
    IncomingChannelNotice, ReaderEvent, SendChannelNoticeError, SshChannel, SshChannelReader,
    SshChannelWriter, WriteChannelCloseError, WriteChannelEofError, WriteDataError,
    WriteExtendedDataError,
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

    #[snafu(display("failed to duplicate PTY file descriptor"))]
    DupFd { source: nix::Error },

    #[snafu(display("failed to set up async PTY master"))]
    AsyncPty { source: std::io::Error },

    #[snafu(display("failed to read from process stdout"))]
    ReadStdout { source: std::io::Error },

    #[snafu(display("failed to read from process stderr"))]
    ReadStderr { source: std::io::Error },

    #[snafu(display("failed to read from PTY master"))]
    ReadPty { source: std::io::Error },

    #[snafu(display("failed to write channel data"))]
    WriteData { source: WriteDataError },

    #[snafu(display("failed to write channel extended data"))]
    WriteExtendedData { source: WriteExtendedDataError },

    #[snafu(display("failed to send exit notification"))]
    SendExit {
        source: SendChannelNoticeError<SessionCodecError>,
    },

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
    Exec { shell: &'a OsStr, command: &'a [u8] },
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
    channel: SshChannel<R, W>,
    mode: CommandMode<'_>,
) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let mut cmd = tokio::process::Command::new(mode.program());
    cmd.args(mode.args())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| setpgid(Pid::from_raw(0), Pid::from_raw(0)).map_err(std::io::Error::other));
    }

    let mut child = cmd.spawn().context(SpawnSnafu)?;
    let stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let pid = child.id().map(|id| Pid::from_raw(id as i32));

    let (reader, mut writer) = channel.into_split();

    let (_, output_result) = tokio::join!(relay_input_piped(reader, stdin, pid), async {
        relay_output_piped(&mut stdout, &mut stderr, &mut writer).await?;
        let status = child.wait().await.context(WaitSnafu)?;
        send_exit_notification(&mut writer, &status).await?;
        writer.eof().await.context(WriteEofSnafu)?;
        writer.close().await.context(WriteCloseSnafu)?;
        writer
            .writer_mut()
            .shutdown()
            .await
            .context(ShutdownSnafu)?;
        Ok::<_, ProcessError>(())
    },);
    output_result
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
    channel: SshChannel<R, W>,
    mode: CommandMode<'_>,
    pty: PtyPair,
) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let stdout_fd = nix::unistd::dup(pty.slave.as_fd()).context(DupFdSnafu)?;
    let stderr_fd = nix::unistd::dup(pty.slave.as_fd()).context(DupFdSnafu)?;

    let mut cmd = tokio::process::Command::new(mode.program());
    cmd.args(mode.args())
        .stdin(pty.slave)
        .stdout(stdout_fd)
        .stderr(stderr_fd);
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            // Set the PTY slave (already on fd 0/1/2) as the controlling terminal.
            // Without this, the shell has no controlling TTY and job control fails
            // ("tcgetpgrp failed", "setpgid: Inappropriate ioctl for device").
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().context(SpawnSnafu)?;
    let pid = child.id().map(|id| Pid::from_raw(id as i32));

    // Use AsyncFd-based wrappers for the PTY master. Unlike tokio::fs::File
    // (which routes every read/write through spawn_blocking and serializes
    // them), AsyncPtyFd uses epoll for near-zero-latency non-blocking I/O.
    // Separate fds for reader and writer avoid any shared state.
    let master_write_fd = nix::unistd::dup(pty.master.as_fd()).context(DupFdSnafu)?;
    let mut master_reader = super::pty::AsyncPtyFd::new(pty.master).context(AsyncPtySnafu)?;
    let master_raw_fd = master_reader.as_raw_fd();
    let master_writer = super::pty::AsyncPtyFd::new(master_write_fd).context(AsyncPtySnafu)?;

    let (reader, mut writer) = channel.into_split();

    let (_, output_result) = tokio::join!(
        relay_input_pty(reader, master_writer, pid, master_raw_fd),
        async {
            let output_result = relay_output_pty(&mut master_reader, &mut writer).await;
            if let Err(ProcessError::ReadPty { ref source }) = output_result
                && source.raw_os_error() != Some(nix::libc::EIO)
            {
                output_result?;
            }
            let status = child.wait().await.context(WaitSnafu)?;
            send_exit_notification(&mut writer, &status).await?;
            writer.eof().await.context(WriteEofSnafu)?;
            writer.close().await.context(WriteCloseSnafu)?;
            writer
                .writer_mut()
                .shutdown()
                .await
                .context(ShutdownSnafu)?;
            Ok::<_, ProcessError>(())
        },
    );
    output_result
}

// ============================================================================
// Output relay
// ============================================================================

/// Multiplex stdout and stderr to the channel writer using `tokio::select!`.
async fn relay_output_piped<W>(
    stdout: &mut (impl AsyncRead + Unpin),
    stderr: &mut (impl AsyncRead + Unpin),
    writer: &mut SshChannelWriter<W>,
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
                writer
                    .data(&stdout_buf[..n])
                    .await
                    .context(WriteDataSnafu)?;
            }
            result = stderr.read(&mut stderr_buf), if !stderr_done => {
                let n = result.context(ReadStderrSnafu)?;
                if n == 0 {
                    stderr_done = true;
                    continue;
                }
                writer
                    .extended_data(
                        VarInt::from(1u8), // SSH_EXTENDED_DATA_STDERR
                        &stderr_buf[..n],
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
    writer: &mut SshChannelWriter<W>,
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
        writer.data(&buf[..n]).await.context(WriteDataSnafu)?;
    }
    Ok(())
}

// ============================================================================
// Input relay
// ============================================================================

/// Read from channel, write data to process stdin, deliver signals.
async fn relay_input_piped<R>(
    mut reader: SshChannelReader<R>,
    mut stdin: impl AsyncWrite + Unpin + Send,
    pid: Option<Pid>,
) where
    R: AsyncRead + Unpin + Send,
{
    loop {
        match reader.next_event().await {
            Ok(ReaderEvent::Data(mut data)) => {
                if io::copy(&mut data, &mut stdin).await.is_err() {
                    break;
                }
            }
            Ok(ReaderEvent::Notice(incoming)) => {
                if !handle_piped_notice(incoming, pid).await {
                    break;
                }
            }
            Ok(ReaderEvent::Eof | ReaderEvent::Close) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Read from channel, write data to PTY master, deliver signals, handle
/// window-change requests.
async fn relay_input_pty<R>(
    mut reader: SshChannelReader<R>,
    mut pty_writer: impl AsyncWrite + Unpin + Send,
    pid: Option<Pid>,
    master_raw_fd: RawFd,
) where
    R: AsyncRead + Unpin + Send,
{
    loop {
        match reader.next_event().await {
            Ok(ReaderEvent::Data(mut data)) => {
                if io::copy(&mut data, &mut pty_writer).await.is_err() {
                    break;
                }
            }
            Ok(ReaderEvent::Notice(incoming)) => {
                if !handle_pty_notice(incoming, pid, master_raw_fd).await {
                    break;
                }
            }
            Ok(ReaderEvent::Eof | ReaderEvent::Close) | Err(_) => break,
            Ok(_) => {}
        }
    }
    drop(pty_writer);
}

// ============================================================================
// Notice handlers for input relay
// ============================================================================

/// Handle a channel notice in piped mode. Returns `true` to continue, `false` to stop.
async fn handle_piped_notice<R: AsyncRead + Unpin + Send>(
    incoming: IncomingChannelNotice<'_, R>,
    pid: Option<Pid>,
) -> bool {
    match &**incoming.request_type() {
        "signal" => {
            let Ok(req) = incoming
                .decode_payload::<SignalRequest, SessionCodecError>()
                .await
            else {
                return false;
            };
            deliver_to_pid(pid, &req.signal_name);
            true
        }
        _ => {
            // Unknown notice in piped mode — can't decode payload, abandon input.
            false
        }
    }
}

/// Handle a channel notice in PTY mode. Returns `true` to continue, `false` to stop.
async fn handle_pty_notice<R: AsyncRead + Unpin + Send>(
    incoming: IncomingChannelNotice<'_, R>,
    pid: Option<Pid>,
    master_raw_fd: RawFd,
) -> bool {
    match &**incoming.request_type() {
        "signal" => {
            let Ok(req) = incoming
                .decode_payload::<SignalRequest, SessionCodecError>()
                .await
            else {
                return false;
            };
            deliver_to_pid(pid, &req.signal_name);
            true
        }
        "window-change" => {
            let Ok(req) = incoming
                .decode_payload::<WindowChangeRequest, SessionCodecError>()
                .await
            else {
                return false;
            };
            if let Err(e) = super::pty::set_window_size_raw(master_raw_fd, &req) {
                tracing::warn!(
                    error = %snafu::Report::from_error(&e),
                    cols = %req.width_cols,
                    rows = %req.height_rows,
                    "window-change resize failed"
                );
            }
            true
        }
        _ => {
            // Unknown notice — can't decode payload, abandon input.
            false
        }
    }
}

fn deliver_to_pid(pid: Option<Pid>, signal_name: &SshString) {
    let Some(pid) = pid else { return };
    let Some(sig) = signal::from_ssh_name(signal_name) else {
        return;
    };
    if let Err(e) = signal::deliver(pid, sig) {
        tracing::warn!(
            error = %snafu::Report::from_error(&e),
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
    writer: &mut SshChannelWriter<W>,
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

        writer
            .notice(&ExitSignalChannelNotice {
                payload: ExitSignalRequest {
                    signal_name: SshString::from(signal_name.into_owned()),
                    core_dumped: SshBool(status.core_dumped()),
                    error_message: SshString::from(""),
                    language_tag: SshString::from(""),
                },
            })
            .await
            .context(SendExitSnafu)?;
    } else {
        let code = status.code().unwrap_or(255) as u32;
        writer
            .notice(&ExitStatusChannelNotice {
                payload: ExitStatusRequest {
                    exit_status: VarInt::from(code),
                },
            })
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
    use crate::conversation::channel::ChannelEvent;

    // Helper: create a mock channel pair (in-memory duplex).
    fn channel_pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    #[tokio::test]
    async fn run_piped_echo() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let handle = tokio::spawn(async move {
            run_piped(
                SshChannel::new(server_reader, server_writer),
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"echo hello",
                },
            )
            .await
        });

        let mut channel = SshChannel::new(client_reader, client_writer);
        let mut all_data = Vec::new();
        loop {
            let event = channel.next_event().await;
            match event {
                Ok(ChannelEvent::Data(mut data)) => {
                    let bytes = data.read_all().await.unwrap();
                    all_data.extend_from_slice(&bytes);
                }
                Ok(ChannelEvent::Request(incoming)) => {
                    if &**incoming.request_type() == "exit-status" {
                        let _ = incoming
                            .decode_payload::<ExitStatusRequest, SessionCodecError>()
                            .await;
                    } else if &**incoming.request_type() == "exit-signal" {
                        let _ = incoming
                            .decode_payload::<ExitSignalRequest, SessionCodecError>()
                            .await;
                    }
                }
                Ok(ChannelEvent::Eof) => {}
                Ok(ChannelEvent::Close) => break,
                Err(_) => break,
                _ => {}
            }
        }

        assert_eq!(String::from_utf8_lossy(&all_data), "hello\n");
        // Drop client channel so server's input relay sees stream close and exits.
        drop(channel);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_piped_stderr() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let handle = tokio::spawn(async move {
            run_piped(
                SshChannel::new(server_reader, server_writer),
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"echo err >&2",
                },
            )
            .await
        });

        let mut channel = SshChannel::new(client_reader, client_writer);
        let mut stderr_data = Vec::new();
        loop {
            match channel.next_event().await {
                Ok(ChannelEvent::ExtendedData {
                    data_type,
                    mut data,
                }) => {
                    assert_eq!(data_type, VarInt::from(1u8));
                    let bytes = data.read_all().await.unwrap();
                    stderr_data.extend_from_slice(&bytes);
                }
                Ok(ChannelEvent::Request(incoming)) => {
                    if &**incoming.request_type() == "exit-status" {
                        let _ = incoming
                            .decode_payload::<ExitStatusRequest, SessionCodecError>()
                            .await;
                    } else if &**incoming.request_type() == "exit-signal" {
                        let _ = incoming
                            .decode_payload::<ExitSignalRequest, SessionCodecError>()
                            .await;
                    }
                }
                Ok(ChannelEvent::Eof) => {}
                Ok(ChannelEvent::Close) => break,
                Err(_) => break,
                _ => {}
            }
        }

        assert_eq!(String::from_utf8_lossy(&stderr_data), "err\n");
        drop(channel);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_piped_exit_code() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let handle = tokio::spawn(async move {
            run_piped(
                SshChannel::new(server_reader, server_writer),
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"exit 42",
                },
            )
            .await
        });

        let mut channel = SshChannel::new(client_reader, client_writer);
        let mut exit_code = None;
        loop {
            match channel.next_event().await {
                Ok(ChannelEvent::Request(incoming)) => {
                    if &**incoming.request_type() == "exit-status" {
                        let (req, _) = incoming
                            .decode_payload::<ExitStatusRequest, SessionCodecError>()
                            .await
                            .unwrap();
                        exit_code = Some(req.exit_status.into_inner() as u32);
                    } else if &**incoming.request_type() == "exit-signal" {
                        let _ = incoming
                            .decode_payload::<ExitSignalRequest, SessionCodecError>()
                            .await;
                    }
                }
                Ok(ChannelEvent::Close) => break,
                Err(_) => break,
                _ => {}
            }
        }

        assert_eq!(exit_code, Some(42));
        drop(channel);
        handle.await.unwrap().unwrap();
    }
}
