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
use std::path::Path;
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
use crate::message::SSH_EXTENDED_DATA_STDERR;
use crate::session::dispatcher::SessionConfig;
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

    /// argv[0] for the spawned process.
    ///
    /// For interactive shells, returns `-<basename>` (login shell convention).
    /// For exec commands, returns the plain basename.
    fn argv0(&self) -> OsString {
        let basename = Path::new(self.program())
            .file_name()
            .unwrap_or(self.program());
        match self {
            Self::Shell { .. } => {
                let mut s = OsString::from("-");
                s.push(basename);
                s
            }
            Self::Exec { .. } => basename.to_os_string(),
        }
    }
}

/// Build the environment variable set for the child process.
///
/// Follows the OpenSSH `do_setup_env` convention: clear the inherited
/// environment entirely, then set a well-known baseline.
fn build_env(
    config: &SessionConfig,
    term: Option<&str>,
    client_env: &[(String, String)],
) -> Vec<(OsString, OsString)> {
    let user = &config.user;
    let mut env: Vec<(OsString, OsString)> = Vec::with_capacity(16);

    env.push(("USER".into(), (&*user.username).into()));
    env.push(("LOGNAME".into(), (&*user.username).into()));
    env.push(("HOME".into(), user.home.as_os_str().into()));
    env.push(("SHELL".into(), user.shell.as_os_str().into()));

    // PATH: root gets sbin directories, normal users do not.
    let path = if user.uid == 0 {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    } else {
        "/usr/local/bin:/usr/bin:/bin"
    };
    env.push(("PATH".into(), path.into()));

    env.push(("MAIL".into(), format!("/var/mail/{}", user.username).into()));

    if let Some(t) = term {
        env.push(("TERM".into(), t.into()));
    }

    // Inherit TZ from parent if set.
    if let Ok(tz) = std::env::var("TZ") {
        env.push(("TZ".into(), tz.into()));
    }

    // Inherit LANG from parent if set (PAM pam_env.so may override via pam_env below).
    if let Ok(lang) = std::env::var("LANG") {
        env.push(("LANG".into(), lang.into()));
    }

    // /etc/environment: system-wide environment variables (inserted before PAM env
    // so that PAM modules can override them).
    for (k, v) in read_environment_file() {
        env.push((k.into(), v.into()));
    }

    // PAM environment (may override earlier entries; last-set-wins since
    // Command::envs uses the last value for duplicate keys).
    for (k, v) in &config.user.pam_env {
        env.push((k.into(), v.into()));
    }

    // Client-requested environment variables (from "env" channel requests).
    for (k, v) in client_env {
        env.push((k.into(), v.into()));
    }

    env
}

/// Read `/etc/environment` and return `KEY=VALUE` pairs.
///
/// Lines that are empty, start with `#`, or do not contain `=` are skipped.
/// Values may optionally be quoted with single or double quotes, which are
/// stripped (matching OpenSSH `read_environment_file` behaviour).
fn read_environment_file() -> Vec<(String, String)> {
    let content = match std::fs::read_to_string("/etc/environment") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let mut value = value.trim();
            // Strip optional quotes (need at least 2 chars for a matching pair).
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                value = &value[1..value.len() - 1];
            }
            if !key.is_empty() {
                result.push((key.to_owned(), value.to_owned()));
            }
        }
    }
    result
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
    config: &SessionConfig,
    term: Option<&str>,
    client_env: &[(String, String)],
) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let home = &config.user.home;
    let cwd = if home.is_dir() {
        home.as_path()
    } else {
        tracing::warn!(home = %home.display(), "home directory does not exist, falling back to /");
        Path::new("/")
    };

    let mut cmd = tokio::process::Command::new(mode.program());
    cmd.arg0(mode.argv0())
        .args(mode.args())
        .env_clear()
        .envs(build_env(config, term, client_env))
        .current_dir(cwd)
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

    let input_handle = tokio::spawn(relay_input_piped(reader, stdin, pid));

    let output_result = async {
        let status = relay_output_piped(&mut stdout, &mut stderr, &mut writer, &mut child).await?;
        send_exit_notification(&mut writer, &status).await?;
        writer.eof().await.context(WriteEofSnafu)?;
        writer.close().await.context(WriteCloseSnafu)?;
        writer
            .writer_mut()
            .shutdown()
            .await
            .context(ShutdownSnafu)?;
        Ok::<_, ProcessError>(())
    }
    .await;

    input_handle.abort();
    let _ = input_handle.await;
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
    config: &SessionConfig,
    term: Option<&str>,
    client_env: &[(String, String)],
) -> Result<(), ProcessError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let stdout_fd = nix::unistd::dup(pty.slave.as_fd()).context(DupFdSnafu)?;
    let stderr_fd = nix::unistd::dup(pty.slave.as_fd()).context(DupFdSnafu)?;

    let home = &config.user.home;
    let cwd = if home.is_dir() {
        home.as_path()
    } else {
        tracing::warn!(home = %home.display(), "home directory does not exist, falling back to /");
        Path::new("/")
    };

    let mut cmd = tokio::process::Command::new(mode.program());
    cmd.arg0(mode.argv0())
        .args(mode.args())
        .env_clear()
        .envs(build_env(config, term, client_env))
        .current_dir(cwd)
        .stdin(pty.slave)
        .stdout(stdout_fd)
        .stderr(stderr_fd);
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            // Set the PTY slave (already on fd 0/1/2) as the controlling terminal.
            // Without this, the shell has no controlling TTY and job control fails
            // ("tcgetpgrp failed", "setpgid: Inappropriate ioctl for device").
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY as nix::libc::c_ulong, 0) < 0 {
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

    let input_handle = tokio::spawn(relay_input_pty(reader, master_writer, pid, master_raw_fd));

    let output_result = async {
        let status = relay_output_pty(&mut master_reader, &mut writer, &mut child).await?;
        tracing::trace!(?status, "child process exited");
        send_exit_notification(&mut writer, &status).await?;
        tracing::trace!("exit notification sent");
        writer.eof().await.context(WriteEofSnafu)?;
        writer.close().await.context(WriteCloseSnafu)?;
        tracing::trace!("eof + close written");
        writer
            .writer_mut()
            .shutdown()
            .await
            .context(ShutdownSnafu)?;
        tracing::trace!("writer shutdown complete");
        Ok::<_, ProcessError>(())
    }
    .await;

    input_handle.abort();
    let _ = input_handle.await;
    output_result
}

// ============================================================================
// Output relay
// ============================================================================

/// Multiplex stdout and stderr to the channel writer, racing each read against
/// child exit. See [`relay_output_pty`] for the rationale.
async fn relay_output_piped<W>(
    stdout: &mut (impl AsyncRead + Unpin),
    stderr: &mut (impl AsyncRead + Unpin),
    writer: &mut SshChannelWriter<W>,
    child: &mut tokio::process::Child,
) -> Result<std::process::ExitStatus, ProcessError>
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
                        SSH_EXTENDED_DATA_STDERR,
                        &stderr_buf[..n],
                    )
                    .await
                    .context(WriteExtendedDataSnafu)?;
            }
            wait_result = child.wait() => {
                return wait_result.context(WaitSnafu);
            }
        }
    }

    child.wait().await.context(WaitSnafu)
}

/// Relay PTY master output to the channel writer, racing each read against
/// child exit.
///
/// On every iteration the function selects between a PTY read and
/// `child.wait()`:
///
/// - **Read wins** — the data is forwarded to `writer`, then the race repeats.
/// - **`child.wait()` wins** — the child has exited and we are at a clean SSH
///   frame boundary (not mid-write), so the caller can safely send
///   `exit-status` / EOF / Close.
/// - **PTY closes (EIO / `Ok(0)`)** — the read loop ends and we wait for the
///   child before returning.
async fn relay_output_pty<W>(
    master: &mut (impl AsyncRead + Unpin),
    writer: &mut SshChannelWriter<W>,
    child: &mut tokio::process::Child,
) -> Result<std::process::ExitStatus, ProcessError>
where
    W: AsyncWrite + Unpin + Send,
{
    use process_error::*;

    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            read_result = master.read(&mut buf) => {
                match read_result {
                    // PTY slave closed — normal shell exit path.
                    Err(ref e) if e.raw_os_error() == Some(nix::libc::EIO) => break,
                    Err(e) => return Err(e).context(ReadPtySnafu),
                    Ok(0) => break,
                    Ok(n) => writer.data(&buf[..n]).await.context(WriteDataSnafu)?,
                }
            }
            wait_result = child.wait() => {
                // Child exited while we were between reads: we are at a clean
                // SSH frame boundary, so the caller can safely send
                // exit-status / EOF / Close.
                return wait_result.context(WaitSnafu);
            }
        }
    }
    // PTY closed cleanly. Wait for the child to confirm exit.
    child.wait().await.context(WaitSnafu)
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
            .unwrap_or_else(|| Cow::Owned(format!("signal-{signal_number}@dssh")));

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
    use crate::session::dispatcher::SessionConfig;

    // Helper: create a mock channel pair (in-memory duplex).
    fn channel_pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    #[tokio::test]
    async fn run_piped_echo() {
        let (client_stream, server_stream) = channel_pair();
        let (server_reader, server_writer) = tokio::io::split(server_stream);
        let (client_reader, client_writer) = tokio::io::split(client_stream);

        let config = SessionConfig::default();
        let handle = tokio::spawn(async move {
            run_piped(
                SshChannel::new(server_reader, server_writer),
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"echo hello",
                },
                &config,
                None,
                &[],
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

        let config = SessionConfig::default();
        let handle = tokio::spawn(async move {
            run_piped(
                SshChannel::new(server_reader, server_writer),
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"echo err >&2",
                },
                &config,
                None,
                &[],
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

        let config = SessionConfig::default();
        let handle = tokio::spawn(async move {
            run_piped(
                SshChannel::new(server_reader, server_writer),
                CommandMode::Exec {
                    shell: OsStr::new("/bin/sh"),
                    command: b"exit 42",
                },
                &config,
                None,
                &[],
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
