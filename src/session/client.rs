//! Client-side session channel management.
//!
//! Provides [`ClientSession`] — a high-level wrapper that opens a session
//! channel, sends setup requests (exec, shell, pty), then runs a concurrent
//! IO relay via [`ClientSession::run`].
//!
//! # Lifecycle
//!
//! 1. Create via [`ClientSession::new`] with an established channel.
//! 2. Send setup requests: [`request_pty`](ClientSession::request_pty),
//!    [`exec`](ClientSession::exec), [`shell`](ClientSession::shell).
//! 3. Call [`run`](ClientSession::run) to relay stdin/stdout/stderr until
//!    the server closes the channel.

use futures::Stream;
use snafu::prelude::*;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::SshString;
use crate::conversation::channel::{
    ReadChannelEventError, ReaderEvent, SendChannelRequestError, SshChannel, SshChannelReader,
    SshChannelWriter,
};
use crate::session::{
    ExecChannelRequest, ExecRequest, ExitSignalRequest, ExitStatusRequest, PtyChannelRequest,
    PtyRequest, SessionCodecError, ShellChannelRequest, WindowChangeChannelNotice,
    WindowChangeRequest,
};

// ============================================================================
// Error types
// ============================================================================

/// Error from setup-phase operations (request_pty, exec, shell).
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SetupError {
    #[snafu(display("failed to send exec request"))]
    SendExec {
        source: SendChannelRequestError<SessionCodecError, std::convert::Infallible>,
    },

    #[snafu(display("failed to send shell request"))]
    SendShell {
        source: SendChannelRequestError<std::convert::Infallible, std::convert::Infallible>,
    },

    #[snafu(display("failed to send pty-req request"))]
    SendPty {
        source: SendChannelRequestError<SessionCodecError, std::convert::Infallible>,
    },
}

/// Error from the IO relay phase ([`ClientSession::run`]).
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RunError {
    #[snafu(display("failed to read channel event"))]
    ReadEvent { source: ReadChannelEventError },

    #[snafu(display("failed to decode exit-status payload"))]
    DecodeExitStatus { source: SessionCodecError },

    #[snafu(display("failed to decode exit-signal payload"))]
    DecodeExitSignal { source: SessionCodecError },

    #[snafu(display("failed to write to stdout"))]
    WriteStdout { source: std::io::Error },

    #[snafu(display("failed to write to stderr"))]
    WriteStderr { source: std::io::Error },
}

// ============================================================================
// Exit result
// ============================================================================

/// How the remote process terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitResult {
    /// Process exited with a status code.
    Status(u32),
    /// Process was killed by a signal.
    Signal {
        signal_name: SshString,
        core_dumped: bool,
    },
}

// ============================================================================
// ClientSession
// ============================================================================

/// A client-side session channel wrapper.
///
/// Holds the reader/writer pair for a session channel and provides
/// ergonomic methods for setup requests and IO relay.
///
/// # Example
///
/// ```rust,ignore
/// let (reader, writer) = conversation.open_channel(&SessionChannelOpen).await?;
/// let mut session = ClientSession::new(SshChannel::new(reader, writer));
/// session.request_pty(&pty_req).await?;
/// session.exec(b"ls -la").await?;
/// let exit = session.run(stdin, stdout, stderr).await?;
/// ```
pub struct ClientSession<R, W> {
    channel: SshChannel<R, W>,
}

impl<R, W> ClientSession<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Create a new client session from an established channel.
    pub fn new(channel: SshChannel<R, W>) -> Self {
        Self { channel }
    }

    /// Send a `pty-req` channel request.
    pub async fn request_pty(&mut self, request: &PtyRequest) -> Result<(), SetupError> {
        use setup_error::*;

        self.channel
            .request(&PtyChannelRequest {
                payload: request.clone(),
            })
            .await
            .context(SendPtySnafu)?;

        Ok(())
    }

    /// Send an `exec` channel request.
    pub async fn exec(&mut self, command: &[u8]) -> Result<(), SetupError> {
        use setup_error::*;

        self.channel
            .request(&ExecChannelRequest {
                payload: ExecRequest {
                    command: crate::codec::SshBytes::from(command.to_vec()),
                },
            })
            .await
            .context(SendExecSnafu)?;

        Ok(())
    }

    /// Send a `shell` channel request.
    pub async fn shell(&mut self) -> Result<(), SetupError> {
        use setup_error::*;

        self.channel
            .request(&ShellChannelRequest)
            .await
            .context(SendShellSnafu)?;

        Ok(())
    }

    /// Run the IO relay until the server closes the channel.
    ///
    /// Concurrently:
    /// - Reads from `stdin` and sends data to the server.
    /// - Reads channel events and copies data to `stdout` / `stderr`.
    ///
    /// Returns the exit result if the server sent `exit-status` or
    /// `exit-signal`, or `None` if the channel closed without one.
    pub async fn run(
        self,
        stdin: impl AsyncRead + Unpin + Send,
        stdout: impl AsyncWrite + Unpin + Send,
        stderr: impl AsyncWrite + Unpin + Send,
    ) -> Result<Option<ExitResult>, RunError> {
        let (reader, writer) = self.channel.into_split();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let (_, output_result) = tokio::join!(
            relay_stdin(stdin, writer, done_rx),
            relay_output(reader, stdout, stderr, done_tx),
        );
        output_result
    }

    /// Run the IO relay with terminal resize forwarding.
    ///
    /// Like [`run`](Self::run), but additionally monitors `resize` for
    /// terminal dimension changes and sends `window-change` channel
    /// notices to the server.
    pub async fn run_interactive(
        self,
        stdin: impl AsyncRead + Unpin + Send,
        stdout: impl AsyncWrite + Unpin + Send,
        stderr: impl AsyncWrite + Unpin + Send,
        resize: impl Stream<Item = (u16, u16)> + Unpin + Send,
    ) -> Result<Option<ExitResult>, RunError> {
        let (reader, writer) = self.channel.into_split();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let (_, output_result) = tokio::join!(
            relay_stdin_interactive(stdin, writer, done_rx, resize),
            relay_output(reader, stdout, stderr, done_tx),
        );
        output_result
    }

    /// Consume the session and return the underlying channel.
    pub fn into_inner(self) -> SshChannel<R, W> {
        self.channel
    }
}

// ============================================================================
// Internal relay functions
// ============================================================================

/// Relay local stdin → channel writer. Stops on stdin EOF or done signal.
async fn relay_stdin<W: AsyncWrite + Unpin + Send>(
    mut stdin: impl AsyncRead + Unpin + Send,
    mut writer: SshChannelWriter<W>,
    mut done_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            biased;
            _ = &mut done_rx => break,
            result = stdin.read(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if writer.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = writer.eof().await;
    let _ = writer.close().await;
    let _ = writer.writer_mut().shutdown().await;
}

/// Relay local stdin → channel writer with terminal resize forwarding.
///
/// In addition to stdin data, monitors `resize` for `(cols, rows)` changes
/// and sends `window-change` channel notices to the server.
async fn relay_stdin_interactive<W: AsyncWrite + Unpin + Send>(
    mut stdin: impl AsyncRead + Unpin + Send,
    mut writer: SshChannelWriter<W>,
    mut done_rx: tokio::sync::oneshot::Receiver<()>,
    mut resize: impl Stream<Item = (u16, u16)> + Unpin + Send,
) {
    use futures::StreamExt;
    use h3x::varint::VarInt;

    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            biased;
            _ = &mut done_rx => break,
            result = stdin.read(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if writer.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            size = resize.next() => {
                let Some((cols, rows)) = size else { continue };
                let notice = WindowChangeChannelNotice {
                    payload: WindowChangeRequest {
                        width_cols: VarInt::from(cols as u32),
                        height_rows: VarInt::from(rows as u32),
                        width_px: VarInt::from_u32(0),
                        height_px: VarInt::from_u32(0),
                    },
                };
                if let Err(e) = writer.notice::<_, SessionCodecError>(&notice).await {
                    tracing::warn!(
                        error = %snafu::Report::from_error(&e),
                        "failed to send window-change notice"
                    );
                }
            }
        }
    }
    let _ = writer.eof().await;
    let _ = writer.close().await;
    let _ = writer.writer_mut().shutdown().await;
}

/// Relay channel events → local stdout/stderr. Returns exit result.
async fn relay_output<R: AsyncRead + Unpin + Send>(
    mut reader: SshChannelReader<R>,
    mut stdout: impl AsyncWrite + Unpin + Send,
    mut stderr: impl AsyncWrite + Unpin + Send,
    done_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<Option<ExitResult>, RunError> {
    use run_error::*;

    let mut exit_result = None;

    let result = async {
        loop {
            let event = match reader.next_event().await {
                Ok(e) => e,
                Err(ReadChannelEventError::DecodeMessageType { source })
                    if source.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => return Err(e).context(ReadEventSnafu),
            };

            match event {
                ReaderEvent::Data(mut data) => {
                    io::copy(&mut data, &mut stdout)
                        .await
                        .context(WriteStdoutSnafu)?;
                }
                ReaderEvent::ExtendedData { mut data, .. } => {
                    io::copy(&mut data, &mut stderr)
                        .await
                        .context(WriteStderrSnafu)?;
                }
                ReaderEvent::Notice(incoming) => match &**incoming.request_type() {
                    "exit-status" => {
                        let req = incoming
                            .decode_payload::<ExitStatusRequest, SessionCodecError>()
                            .await
                            .context(DecodeExitStatusSnafu)?;
                        exit_result = Some(ExitResult::Status(req.exit_status.into_inner() as u32));
                    }
                    "exit-signal" => {
                        let req = incoming
                            .decode_payload::<ExitSignalRequest, SessionCodecError>()
                            .await
                            .context(DecodeExitSignalSnafu)?;
                        exit_result = Some(ExitResult::Signal {
                            signal_name: req.signal_name,
                            core_dumped: req.core_dumped.0,
                        });
                    }
                    _ => {
                        // Unknown notice — can't decode payload, stream is inconsistent.
                        break;
                    }
                },
                ReaderEvent::Eof => {}
                ReaderEvent::Close => break,
                _ => {}
            }
        }
        Ok(exit_result)
    }
    .await;

    // Always signal the stdin relay to stop, even on error.
    let _ = done_tx.send(());
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::channel::SshChannel;
    use h3x::varint::VarInt;

    fn channel_pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    #[tokio::test]
    async fn run_stdout_relay() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);
        let (_server_reader, server_writer) = tokio::io::split(server);

        // Server sends data, EOF, close.
        let mut sw = SshChannel::new(_server_reader, server_writer);
        sw.data(b"hello").await.unwrap();
        sw.eof().await.unwrap();
        sw.close().await.unwrap();
        sw.writer_mut().shutdown().await.unwrap();

        let session = ClientSession::new(SshChannel::new(client_reader, client_writer));
        let (stdout_tx, mut stdout_rx) = tokio::io::duplex(64 * 1024);
        let result = session
            .run(tokio::io::empty(), stdout_tx, tokio::io::sink())
            .await
            .unwrap();

        assert_eq!(result, None);

        let mut buf = Vec::new();
        stdout_rx.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");
    }

    #[tokio::test]
    async fn run_stderr_relay() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);
        let (_server_reader, server_writer) = tokio::io::split(server);

        let mut sw = SshChannel::new(_server_reader, server_writer);
        sw.extended_data(VarInt::from(1u8), b"err").await.unwrap();
        sw.eof().await.unwrap();
        sw.close().await.unwrap();
        sw.writer_mut().shutdown().await.unwrap();

        let session = ClientSession::new(SshChannel::new(client_reader, client_writer));
        let (stderr_tx, mut stderr_rx) = tokio::io::duplex(64 * 1024);
        let result = session
            .run(tokio::io::empty(), tokio::io::sink(), stderr_tx)
            .await
            .unwrap();

        assert_eq!(result, None);

        let mut buf = Vec::new();
        stderr_rx.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"err");
    }

    #[tokio::test]
    async fn run_exit_status() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);
        let (_server_reader, server_writer) = tokio::io::split(server);

        let mut sw = SshChannel::new(_server_reader, server_writer);
        sw.notice(&crate::session::ExitStatusChannelNotice {
            payload: ExitStatusRequest {
                exit_status: VarInt::from(42u32),
            },
        })
        .await
        .unwrap();
        sw.eof().await.unwrap();
        sw.close().await.unwrap();
        sw.writer_mut().shutdown().await.unwrap();

        let session = ClientSession::new(SshChannel::new(client_reader, client_writer));
        let result = session
            .run(tokio::io::empty(), tokio::io::sink(), tokio::io::sink())
            .await
            .unwrap();

        assert_eq!(result, Some(ExitResult::Status(42)));
    }

    #[tokio::test]
    async fn run_stream_eof_returns_none() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);

        // Drop server side to cause EOF.
        drop(server);

        let session = ClientSession::new(SshChannel::new(client_reader, client_writer));
        let result = session
            .run(tokio::io::empty(), tokio::io::sink(), tokio::io::sink())
            .await
            .unwrap();

        assert_eq!(result, None);
    }
}
