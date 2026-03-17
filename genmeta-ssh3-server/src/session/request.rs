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

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

use genmeta_ssh3_proto::{
    codec::{SshBool, SshString},
    message::SshMessage,
};
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use nix::{
    errno::Errno,
    sys::signal::{self, Signal},
    unistd::{Pid, dup, setpgid},
};
use snafu::{Report, ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::Instrument;

use crate::channel::ChannelEvent;
use crate::session::pty::{PtyPair, PtyRequest, SignalRequest, WindowChangeRequest, set_window_size};
// ---------------------------------------------------------------------------
// Parsed request types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: Vec<u8>,
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

#[derive(Debug, Snafu)]
pub enum RequestCodecError {
    #[snafu(display("request codec I/O error: {source}"), context(false))]
    Io { source: io::Error },

    #[snafu(display("request codec VarInt conversion error: {source}"))]
    VarIntConversion { source: h3x::varint::err::Overflow },
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExecRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let len: VarInt = stream.decode_one().await?;
        let mut command = vec![0u8; len.into_inner() as usize];
        stream.read_exact(&mut command).await?;
        Ok(Self { command })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ExecRequest {
    type Output = ();
    type Error = RequestCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(VarInt::try_from(self.command.len() as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream.write_all(&self.command).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SubsystemRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let subsystem_name: SshString = stream.decode_one().await?;
        Ok(Self {
            subsystem_name: subsystem_name.0,
        })
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitStatusRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let exit_status: VarInt = stream.decode_one().await?;
        Ok(Self {
            exit_status: exit_status.into_inner() as u32,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ExitStatusRequest {
    type Output = ();
    type Error = RequestCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(VarInt::try_from(self.exit_status as u64).context(VarIntConversionSnafu)?)
            .await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitSignalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let signal_name: SshString = stream.decode_one().await?;
        let core_dumped: SshBool = stream.decode_one().await?;
        let error_message: SshString = stream.decode_one().await?;
        let language_tag: SshString = stream.decode_one().await?;
        Ok(Self {
            signal_name: signal_name.0,
            core_dumped: core_dumped.0,
            error_message: error_message.0,
            language_tag: language_tag.0,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ExitSignalRequest {
    type Output = ();
    type Error = RequestCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.signal_name.clone())).await?;
        stream.encode_one(SshBool(self.core_dumped)).await?;
        stream.encode_one(SshString(self.error_message.clone())).await?;
        stream.encode_one(SshString(self.language_tag.clone())).await?;
        Ok(())
    }
}

/// Action returned by [`handle_request`] indicating what the caller should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAction {
    /// Run `exec` with the given command string.
    Exec(Vec<u8>),
    /// Launch an interactive shell.
    Shell,
    /// Allocate a PTY with the given parameters.
    /// The `bool` carries `want_reply` so the caller can send success/failure
    /// AFTER allocation completes (not before).
    AllocatePty(PtyRequest, bool),
    /// Resize the terminal window.
    WindowChange(WindowChangeRequest),
    /// Deliver a signal to the running process.
    Signal(SignalRequest),
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

#[cfg(test)]
fn default_shell() -> &'static OsStr {
    OsStr::new("/bin/sh")
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
            let command = ExecRequest::decode_from(request_data).await?.command;
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
            let req = PtyRequest::decode_from(request_data).await?;
            // Reply is deferred to the caller — sent only after allocation
            // succeeds or fails (see session_driver.rs / channel.rs).
            Ok(Some(RequestAction::AllocatePty(req, want_reply)))
        }
        "window-change" => {
            let req = WindowChangeRequest::decode_from(request_data).await?;
            if want_reply {
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::WindowChange(req)))
        }
        "signal" => {
            let req = SignalRequest::decode_from(request_data).await?;
            if want_reply {
                SshMessage::ChannelSuccess.encode_into(writer).await?;
            }
            Ok(Some(RequestAction::Signal(req)))
        }
        "subsystem" => {
            // MVP: subsystem not implemented, return failure.
            let _req = SubsystemRequest::decode_from(request_data).await?;
            if want_reply {
                SshMessage::ChannelFailure.encode_into(writer).await?;
            }
            Ok(None)
        }
        "exit-status" => {
            // Server→client direction: parse and acknowledge (no action needed).
            let _req = ExitStatusRequest::decode_from(request_data).await?;
            Ok(None)
        }
        "exit-signal" => {
            // Server→client direction: parse and acknowledge (no action needed).
            let _req = ExitSignalRequest::decode_from(request_data).await?;
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

/// Spawn `<shell> -c <command>`, copy stdout → ChannelData, stderr →
/// ChannelExtendedData, then send exit-status + EOF + Close.
///
/// When `pty` is `Some`, the child process uses the PTY slave as stdin/stdout/stderr,
/// and the PTY master is used for I/O relay.
pub async fn run_exec<W>(
    shell_path: &OsStr,
    command: &[u8],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
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
    args: &[OsString],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
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
            SshMessage::ChannelFailure.encode_into(writer).await?;
            return Err(e);
        }
    };

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let stdin = child.stdin.take().unwrap();
    let child_pid = child.id().unwrap_or(0) as i32;

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
                ChannelEvent::Request {
                    request_type,
                    request_data,
                    ..
                } if request_type == "signal" => {
                    if let Err(error) = deliver_signal_request(child_pid, &request_data).await {
                        tracing::warn!(error = %Report::from_error(&error), child_pid, "failed to deliver signal to non-PTY child");
                    }
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
            data_type: VarInt::from(1u8),
            data: stderr_data,
        }
        .encode_into(&mut *writer)
        .await?;
    }

    stdout_result?;

    // Wait for process to exit.
    let status = child.wait().await?;
    if let Some(signal_number) = status.signal() {
        let signal_name = exit_signal_name(signal_number);
        let mut request_data = Vec::new();
        request_data
            .encode_one(&ExitSignalRequest {
                signal_name: signal_name.into_owned(),
                core_dumped: status.core_dumped(),
                error_message: String::new(),
                language_tag: String::new(),
            })
            .await
            .map_err(io::Error::other)?;
        SshMessage::ChannelRequest {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut *writer)
        .await?;
    } else {
        let exit_code = status.code().unwrap_or(255) as u32;
        let mut request_data = Vec::new();
        request_data
            .encode_one(&ExitStatusRequest { exit_status: exit_code })
            .await
            .map_err(io::Error::other)?;
        SshMessage::ChannelRequest {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut *writer)
        .await?;
    }

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
    args: &[OsString],
    writer: &mut W,
    event_rx: mpsc::Receiver<ChannelEvent>,
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
                            if let Err(error) = deliver_signal_request(child_pid, &request_data).await {
                                tracing::warn!(error = %Report::from_error(&error), child_pid, "failed to deliver signal to PTY child");
                            }
                        }
                        "window-change" => {
                            if let Ok(req) = WindowChangeRequest::decode_from(request_data.as_slice()).await {
                                if let Err(error) = set_window_size(master_raw_fd, &req) {
                                    tracing::warn!(
                                        error = %Report::from_error(&error),
                                        width_cols = req.width_cols,
                                        height_rows = req.height_rows,
                                        "window-change resize failed, keeping current size"
                                    );
                                }
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

    // Wait for process to exit — use the same signal-aware split as non-PTY.
    let status = child.wait().await?;
    if let Some(signal_number) = status.signal() {
        let signal_name = exit_signal_name(signal_number);
        let mut request_data = Vec::new();
        request_data
            .encode_one(&ExitSignalRequest {
                signal_name: signal_name.into_owned(),
                core_dumped: status.core_dumped(),
                error_message: String::new(),
                language_tag: String::new(),
            })
            .await
            .map_err(io::Error::other)?;
        SshMessage::ChannelRequest {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut *writer)
        .await?;
    } else {
        let exit_code = status.code().unwrap_or(255) as u32;
        let mut request_data = Vec::new();
        request_data
            .encode_one(&ExitStatusRequest { exit_status: exit_code })
            .await
            .map_err(io::Error::other)?;
        SshMessage::ChannelRequest {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut *writer)
        .await?;
    }

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
        }
        .encode_into(&mut *writer)
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

async fn deliver_signal_request(child_pid: i32, request_data: &[u8]) -> io::Result<()> {
    if child_pid <= 0 {
        return Ok(());
    }

    let req = SignalRequest::decode_from(request_data).await?;
    let Some(signal_number) = signal_number(req.signal_name.as_str()) else {
        return Ok(());
    };

    let child_pid = Pid::from_raw(child_pid);
    match signal::killpg(child_pid, signal_number) {
        Ok(()) => Ok(()),
        Err(Errno::ESRCH) => signal::kill(child_pid, signal_number).map_err(io::Error::other),
        Err(error) => Err(io::Error::other(error)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::{codec::SshString, message::SshMessage};
    use h3x::codec::EncodeExt;
    use tokio::io::duplex;

    async fn encode_request_data<T, E>(item: T) -> Result<Vec<u8>, E>
    where
        for<'a> T: EncodeInto<&'a mut Vec<u8>, Output = (), Error = E>,
    {
        let mut buf = Vec::new();
        buf.encode_one(item).await?;
        Ok(buf)
    }

    // -------------------------------------------------------------------
    // Test 1: exec request codec parses SshString payloads
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exec_request_codec_simple() {
        // Encode "echo hello" as SshString
        let (mut writer, mut reader) = duplex(4096);
        SshString("echo hello".into())
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let req = ExecRequest::decode_from(buf.as_slice()).await.unwrap();
        assert_eq!(req.command, b"echo hello");
    }

    #[tokio::test]
    async fn exec_request_codec_empty() {
        // Encode empty string as SshString
        let (mut writer, mut reader) = duplex(4096);
        SshString(String::new())
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let req = ExecRequest::decode_from(buf.as_slice()).await.unwrap();
        assert_eq!(req.command, b"");
    }

    #[tokio::test]
    async fn exec_request_codec_non_utf8() {
        let request_data = vec![0x03, 0x66, 0x6f, 0xff];

        let req = ExecRequest::decode_from(request_data.as_slice()).await.unwrap();
        assert_eq!(req.command, vec![0x66, 0x6f, 0xff]);
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
            SshMessage::ChannelData { data } => String::from_utf8_lossy(data).contains("hello"),
            _ => false,
        });
        assert!(
            has_hello,
            "expected ChannelData containing 'hello', got: {messages:?}"
        );

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
            messages
                .iter()
                .any(|m| matches!(m, SshMessage::ChannelClose)),
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
            messages
                .iter()
                .any(|m| matches!(m, SshMessage::ChannelClose)),
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
        SshString("sftp".into())
            .encode_into(&mut request_data_buf)
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
        SshString("ls -la".into())
            .encode_into(&mut enc_writer)
            .await
            .unwrap();
        drop(enc_writer);
        let mut request_data = Vec::new();
        enc_reader.read_to_end(&mut request_data).await.unwrap();

        let event = ChannelEvent::Request {
            request_type: "exec".into(),
            want_reply: true,
            request_data,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert_eq!(result, Some(RequestAction::Exec(b"ls -la".to_vec())));

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
    // Test 7: exit-status request codec roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_request_codec_roundtrip() {
        let data = encode_request_data(&ExitStatusRequest { exit_status: 42 })
            .await
            .unwrap();
        let req = ExitStatusRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.exit_status, 42);
    }

    #[tokio::test]
    async fn exit_status_request_codec_zero() {
        let data = encode_request_data(&ExitStatusRequest { exit_status: 0 })
            .await
            .unwrap();
        let req = ExitStatusRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.exit_status, 0);
    }

    #[tokio::test]
    async fn exit_status_request_codec_255() {
        let data = encode_request_data(&ExitStatusRequest { exit_status: 255 })
            .await
            .unwrap();
        let req = ExitStatusRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.exit_status, 255);
    }

    // -------------------------------------------------------------------
    // Test 8: exit-signal request codec roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_signal_request_codec_roundtrip() {
        let data = encode_request_data(&ExitSignalRequest {
            signal_name: "KILL".into(),
            core_dumped: true,
            error_message: "killed by signal".into(),
            language_tag: "en".into(),
        })
            .await
            .unwrap();
        let req = ExitSignalRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.signal_name, "KILL");
        assert!(req.core_dumped);
        assert_eq!(req.error_message, "killed by signal");
        assert_eq!(req.language_tag, "en");
    }

    #[tokio::test]
    async fn exit_signal_request_codec_no_core_dump() {
        let data = encode_request_data(&ExitSignalRequest {
            signal_name: "TERM".into(),
            core_dumped: false,
            error_message: "terminated".into(),
            language_tag: String::new(),
        })
            .await
            .unwrap();
        let req = ExitSignalRequest::decode_from(data.as_slice()).await.unwrap();
        assert_eq!(req.signal_name, "TERM");
        assert!(!req.core_dumped);
        assert_eq!(req.error_message, "terminated");
        assert_eq!(req.language_tag, "");
    }

    // -------------------------------------------------------------------
    // Test 9: exit-status channel request encoding
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_status_channel_request_message() {
        let (mut writer, mut reader) = duplex(8192);
        let mut request_data = Vec::new();
        request_data
            .encode_one(&ExitStatusRequest { exit_status: 42 })
            .await
            .unwrap();
        SshMessage::ChannelRequest {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut writer)
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
                assert_eq!(request_type, "exit-status");
                assert!(!want_reply);
                let req = ExitStatusRequest::decode_from(request_data.as_slice()).await.unwrap();
                assert_eq!(req.exit_status, 42);
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 10: exit-signal channel request encoding
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn exit_signal_channel_request_message() {
        let (mut writer, mut reader) = duplex(8192);
        let mut request_data = Vec::new();
        request_data
            .encode_one(&ExitSignalRequest {
                signal_name: "TERM".into(),
                core_dumped: false,
                error_message: "terminated".into(),
                language_tag: "en".into(),
            })
            .await
            .unwrap();
        SshMessage::ChannelRequest {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut writer)
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
                let req = ExitSignalRequest::decode_from(request_data.as_slice()).await.unwrap();
                assert_eq!(req.signal_name, "TERM");
                assert!(!req.core_dumped);
                assert_eq!(req.error_message, "terminated");
                assert_eq!(req.language_tag, "en");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 11: subsystem request codec
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_subsystem_name() {
        let mut buf = Vec::new();
        SshString("sftp".into())
            .encode_into(&mut buf)
            .await
            .unwrap();
        let req = SubsystemRequest::decode_from(buf.as_slice()).await.unwrap();
        assert_eq!(req.subsystem_name, "sftp");
    }

    // -------------------------------------------------------------------
    // Test 12: handle_request exit-status dispatch
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_request_exit_status() {
        let (server_writer, _client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let request_data = encode_request_data(&ExitStatusRequest { exit_status: 0 })
            .await
            .unwrap();
        let event = ChannelEvent::Request {
            request_type: "exit-status".into(),
            want_reply: false,
            request_data,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
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

        let request_data = encode_request_data(&ExitSignalRequest {
            signal_name: "KILL".into(),
            core_dumped: true,
            error_message: "killed".into(),
            language_tag: "en".into(),
        })
            .await
            .unwrap();
        let event = ChannelEvent::Request {
            request_type: "exit-signal".into(),
            want_reply: false,
            request_data,
        };

        let result = handle_request(&event, &mut server_writer).await.unwrap();
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
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected error: {e}"),
            };
            match &msg {
                SshMessage::ChannelRequest { request_type, .. }
                    if request_type == "exit-status" =>
                {
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
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        // Find ChannelExtendedData with stderr
        let has_stderr = messages.iter().any(|m| match m {
            SshMessage::ChannelExtendedData { data_type, data } => {
                *data_type == VarInt::from(1u8)
                    && String::from_utf8_lossy(data).contains("stderr_msg")
            }
            _ => false,
        });
        assert!(
            has_stderr,
            "expected ChannelExtendedData with stderr_msg, got: {messages:?}"
        );
    }

    // -------------------------------------------------------------------
    // Test 16: PTY signal termination emits exit-signal, not exit-status
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pty_signal_emits_exit_signal_instead_of_exit_status() {
        use crate::session::pty::{PtyRequest, allocate_pty};

        let pty_req = PtyRequest {
            term_type: "xterm".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
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
        let mut request_data = Vec::new();
        SshString("TERM".into())
            .encode_into(&mut request_data)
            .await
            .unwrap();
        event_tx
            .send(ChannelEvent::Request {
                request_type: "signal".into(),
                want_reply: false,
                request_data,
            })
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
                Ok(SshMessage::ChannelRequest {
                    request_type,
                    want_reply,
                    request_data,
                    ..
                }) if request_type == "exit-signal" => {
                    let req = ExitSignalRequest::decode_from(request_data.as_slice()).await.unwrap();
                    assert_eq!(req.signal_name, "TERM");
                    assert_eq!(req.error_message, "");
                    assert_eq!(req.language_tag, "");
                    assert!(!want_reply, "exit-signal must have want_reply=false");
                    saw_exit_signal = true;
                }
                Ok(SshMessage::ChannelRequest { request_type, .. })
                    if request_type == "exit-status" =>
                {
                    saw_exit_status = true;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
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
        use crate::session::pty::{PtyRequest, allocate_pty};

        let pty_req = PtyRequest {
            term_type: "xterm".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
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
                Ok(SshMessage::ChannelRequest {
                    request_type,
                    want_reply,
                    request_data,
                    ..
                }) if request_type == "exit-status" => {
                    assert!(!want_reply, "exit-status must have want_reply=false");
                    let req = ExitStatusRequest::decode_from(request_data.as_slice()).await.unwrap();
                    assert_eq!(req.exit_status, 42);
                    saw_exit_status = true;
                }
                Ok(SshMessage::ChannelRequest { request_type, .. })
                    if request_type == "exit-signal" =>
                {
                    saw_exit_signal = true;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
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

        let mut request_data = Vec::new();
        SshString("TERM".into())
            .encode_into(&mut request_data)
            .await
            .unwrap();
        event_tx
            .send(ChannelEvent::Request {
                request_type: "signal".into(),
                want_reply: false,
                request_data,
            })
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
                Ok(SshMessage::ChannelRequest {
                    request_type,
                    request_data,
                    ..
                }) if request_type == "exit-signal" => {
                    let req = ExitSignalRequest::decode_from(request_data.as_slice()).await.unwrap();
                    assert_eq!(req.signal_name, "TERM");
                    assert_eq!(req.error_message, "");
                    assert_eq!(req.language_tag, "");
                    saw_exit_signal = true;
                }
                Ok(SshMessage::ChannelRequest { request_type, .. })
                    if request_type == "exit-status" =>
                {
                    saw_exit_status = true;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
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
        let mut request_data = Vec::new();
        SshString("xterm".into())
            .encode_into(&mut request_data)
            .await
            .unwrap();
        let zero = VarInt::try_from(80u64).unwrap();
        request_data.encode_one(zero).await.unwrap();
        let zero = VarInt::try_from(24u64).unwrap();
        request_data.encode_one(zero).await.unwrap();
        let zero = VarInt::from(0u8);
        request_data.encode_one(zero).await.unwrap();
        let zero = VarInt::from(0u8);
        request_data.encode_one(zero).await.unwrap();
        let modes_len = VarInt::from(0u8);
        request_data.encode_one(modes_len).await.unwrap();

        let event = ChannelEvent::Request {
            request_type: "pty-req".into(),
            want_reply: true,
            request_data,
        };

        let (server_writer, mut client_reader) = duplex(8192);
        let mut server_writer = server_writer;

        let result = handle_request(&event, &mut server_writer).await.unwrap();
        assert!(
            matches!(result, Some(RequestAction::AllocatePty(_, true))),
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
        let mut request_data = Vec::new();
        SshString("vt100".into())
            .encode_into(&mut request_data)
            .await
            .unwrap();
        for &val in &[80u64, 24, 0, 0, 0] {
            let v = VarInt::try_from(val).unwrap();
            request_data.encode_one(v).await.unwrap();
        }

        let event_true = ChannelEvent::Request {
            request_type: "pty-req".into(),
            want_reply: true,
            request_data: request_data.clone(),
        };
        let event_false = ChannelEvent::Request {
            request_type: "pty-req".into(),
            want_reply: false,
            request_data,
        };

        let (mut w1, _r1) = duplex(8192);
        let (mut w2, _r2) = duplex(8192);

        let result_true = handle_request(&event_true, &mut w1).await.unwrap();
        let result_false = handle_request(&event_false, &mut w2).await.unwrap();

        match result_true {
            Some(RequestAction::AllocatePty(_, wr)) => assert!(wr, "want_reply should be true"),
            other => panic!("expected AllocatePty, got {other:?}"),
        }
        match result_false {
            Some(RequestAction::AllocatePty(_, wr)) => assert!(!wr, "want_reply should be false"),
            other => panic!("expected AllocatePty, got {other:?}"),
        }
    }
}
