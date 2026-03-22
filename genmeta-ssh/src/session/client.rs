//! Client-side session channel management.
//!
//! Provides [`ClientSession`] — a high-level wrapper that opens a session
//! channel, sends requests (exec, shell, pty), and reads events (stdout,
//! stderr, exit status).
//!
//! Built entirely on the trait-based channel API — no intermediate buffers
//! or enum dispatch.

use h3x::varint::VarInt;
use snafu::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{SshBytes, SshString};
use crate::conversation::{
    ChannelEvent, ReadChannelEventError,
    SendChannelNoticeError, SendChannelRequestError, WriteChannelCloseError,
    WriteChannelDataError, WriteChannelEofError, read_channel_event, send_channel_notice,
    send_channel_request, write_channel_close, write_channel_data, write_channel_eof,
};
use crate::session::{
    ExecChannelRequest, ExecRequest, ExitSignalRequest, ExitStatusRequest,
    PtyChannelRequest, PtyRequest, SessionCodecError, ShellChannelRequest,
    SignalChannelNotice, SignalRequest, WindowChangeChannelNotice, WindowChangeRequest,
};

// ============================================================================
// Error types
// ============================================================================

/// Error from client session operations.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ClientSessionError {
    #[snafu(display("failed to send exec request"))]
    SendExec { source: SendChannelRequestError<SessionCodecError, std::convert::Infallible> },

    #[snafu(display("failed to send shell request"))]
    SendShell { source: SendChannelRequestError<std::convert::Infallible, std::convert::Infallible> },

    #[snafu(display("failed to send pty-req request"))]
    SendPty { source: SendChannelRequestError<SessionCodecError, std::convert::Infallible> },

    #[snafu(display("failed to send window-change notification"))]
    SendWindowChange { source: SendChannelNoticeError<SessionCodecError> },

    #[snafu(display("failed to send signal notification"))]
    SendSignal { source: SendChannelNoticeError<SessionCodecError> },

    #[snafu(display("failed to write stdin data"))]
    WriteStdin { source: WriteChannelDataError },

    #[snafu(display("failed to send EOF"))]
    WriteEof { source: WriteChannelEofError },

    #[snafu(display("failed to send close"))]
    WriteClose { source: WriteChannelCloseError },

    #[snafu(display("failed to read channel event"))]
    ReadEvent { source: ReadChannelEventError },

    #[snafu(display("failed to decode exit-status payload"))]
    DecodeExitStatus { source: SessionCodecError },

    #[snafu(display("failed to decode exit-signal payload"))]
    DecodeExitSignal { source: SessionCodecError },

    #[snafu(display("failed to shutdown channel writer"))]
    Shutdown { source: std::io::Error },
}

// ============================================================================
// Session events
// ============================================================================

/// An event received from the server on a session channel.
#[derive(Debug)]
pub enum SessionEvent {
    /// Standard output data.
    Stdout(SshBytes),
    /// Standard error data (extended data type 1).
    Stderr(SshBytes),
    /// Process exited with status code.
    ExitStatus(u32),
    /// Process killed by signal.
    ExitSignal {
        signal_name: SshString,
        core_dumped: bool,
    },
    /// Server sent EOF.
    Eof,
    /// Server closed the channel.
    Close,
    /// Server sent success (generic).
    Success,
    /// Server sent failure (generic).
    Failure,
}

// ============================================================================
// ClientSession
// ============================================================================

/// A client-side session channel wrapper.
///
/// Holds the reader/writer pair for a session channel and provides
/// ergonomic methods for sending requests and receiving events.
///
/// # Example
///
/// ```rust,ignore
/// let (reader, writer) = conversation.open_channel(&SessionChannelOpen).await?;
/// let mut session = ClientSession::new(reader, writer);
/// session.request_pty(&pty_req).await?;
/// session.exec(b"ls -la").await?;
/// while let Some(event) = session.recv_event().await? {
///     match event {
///         SessionEvent::Stdout(data) => { /* print */ }
///         SessionEvent::ExitStatus(code) => break,
///         _ => {}
///     }
/// }
/// ```
pub struct ClientSession<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> ClientSession<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// Create a new client session from a channel stream pair.
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    /// Send a `pty-req` channel request.
    pub async fn request_pty(&mut self, request: &PtyRequest) -> Result<(), ClientSessionError> {
        use client_session_error::*;

        send_channel_request(
            &mut self.reader,
            &mut self.writer,
            &PtyChannelRequest {
                payload: request.clone(),
            },
        )
        .await
        .context(SendPtySnafu)?;

        Ok(())
    }

    /// Send an `exec` channel request.
    pub async fn exec(&mut self, command: &[u8]) -> Result<(), ClientSessionError> {
        use client_session_error::*;

        send_channel_request(
            &mut self.reader,
            &mut self.writer,
            &ExecChannelRequest {
                payload: ExecRequest {
                    command: SshBytes::from(command.to_vec()),
                },
            },
        )
        .await
        .context(SendExecSnafu)?;

        Ok(())
    }

    /// Send a `shell` channel request.
    pub async fn shell(&mut self) -> Result<(), ClientSessionError> {
        use client_session_error::*;

        send_channel_request(
            &mut self.reader,
            &mut self.writer,
            &ShellChannelRequest,
        )
        .await
        .context(SendShellSnafu)?;

        Ok(())
    }

    /// Send a `window-change` notification (no reply expected).
    pub async fn window_change(
        &mut self,
        request: &WindowChangeRequest,
    ) -> Result<(), ClientSessionError> {
        use client_session_error::*;

        send_channel_notice(
            &mut self.writer,
            &WindowChangeChannelNotice {
                payload: request.clone(),
            },
        )
        .await
        .context(SendWindowChangeSnafu)?;

        Ok(())
    }

    /// Send a `signal` notification (no reply expected).
    pub async fn signal(&mut self, signal_name: &str) -> Result<(), ClientSessionError> {
        use client_session_error::*;

        send_channel_notice(
            &mut self.writer,
            &SignalChannelNotice {
                payload: SignalRequest {
                    signal_name: SshString::from(signal_name.to_owned()),
                },
            },
        )
        .await
        .context(SendSignalSnafu)?;

        Ok(())
    }

    /// Send stdin data to the remote process.
    pub async fn send_stdin(&mut self, data: &[u8]) -> Result<(), ClientSessionError> {
        use client_session_error::*;
        write_channel_data(&mut self.writer, SshBytes::from(data.to_vec()))
            .await
            .context(WriteStdinSnafu)
    }

    /// Send EOF to the remote process.
    pub async fn send_eof(&mut self) -> Result<(), ClientSessionError> {
        use client_session_error::*;
        write_channel_eof(&mut self.writer).await.context(WriteEofSnafu)
    }

    /// Send close and shutdown the writer.
    pub async fn close(&mut self) -> Result<(), ClientSessionError> {
        use client_session_error::*;
        write_channel_close(&mut self.writer).await.context(WriteCloseSnafu)?;
        self.writer.shutdown().await.context(ShutdownSnafu)?;
        Ok(())
    }

    /// Read the next session event from the channel.
    ///
    /// Returns `None` on EOF (stream closed cleanly).
    pub async fn recv_event(&mut self) -> Result<Option<SessionEvent>, ClientSessionError> {
        use client_session_error::*;

        let event = match read_channel_event(&mut self.reader).await {
            Ok(e) => e,
            Err(ReadChannelEventError::DecodeMessageType { source })
                if source.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e).context(ReadEventSnafu),
        };

        match event {
            ChannelEvent::Data(data) => Ok(Some(SessionEvent::Stdout(data))),
            ChannelEvent::ExtendedData { data, .. } => Ok(Some(SessionEvent::Stderr(data))),
            ChannelEvent::Request(incoming) => {
                match &**incoming.request_type() {
                    "exit-status" => {
                        let (req, _responder) = incoming
                            .decode_payload::<ExitStatusRequest, SessionCodecError>()
                            .await
                            .context(DecodeExitStatusSnafu)?;
                        Ok(Some(SessionEvent::ExitStatus(
                            req.exit_status.into_inner() as u32,
                        )))
                    }
                    "exit-signal" => {
                        let (req, _responder) = incoming
                            .decode_payload::<ExitSignalRequest, SessionCodecError>()
                            .await
                            .context(DecodeExitSignalSnafu)?;
                        Ok(Some(SessionEvent::ExitSignal {
                            signal_name: req.signal_name,
                            core_dumped: req.core_dumped.0,
                        }))
                    }
                    _ => {
                        // Unknown request type — can't decode, stream is inconsistent.
                        Ok(None)
                    }
                }
            }
            ChannelEvent::Success => Ok(Some(SessionEvent::Success)),
            ChannelEvent::Failure => Ok(Some(SessionEvent::Failure)),
            ChannelEvent::Eof => Ok(Some(SessionEvent::Eof)),
            ChannelEvent::Close => Ok(Some(SessionEvent::Close)),
        }
    }

    /// Consume the session and return the underlying streams.
    pub fn into_streams(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::{
        write_channel_data, write_channel_eof, write_channel_close,
    };
    use h3x::codec::EncodeExt;

    fn channel_pair() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    #[tokio::test]
    async fn recv_stdout_data() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);
        let (_server_reader, mut server_writer) = tokio::io::split(server);

        // Server sends data then close.
        write_channel_data(&mut server_writer, SshBytes::from(b"hello".to_vec()))
            .await
            .unwrap();
        write_channel_eof(&mut server_writer).await.unwrap();
        write_channel_close(&mut server_writer).await.unwrap();

        let mut session = ClientSession::new(client_reader, client_writer);

        match session.recv_event().await.unwrap().unwrap() {
            SessionEvent::Stdout(data) => assert_eq!(data.as_ref().as_ref(), b"hello"),
            other => panic!("expected Stdout, got {other:?}"),
        }
        match session.recv_event().await.unwrap().unwrap() {
            SessionEvent::Eof => {}
            other => panic!("expected Eof, got {other:?}"),
        }
        match session.recv_event().await.unwrap().unwrap() {
            SessionEvent::Close => {}
            other => panic!("expected Close, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_exit_status() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);
        let (_server_reader, mut server_writer) = tokio::io::split(server);

        // Server sends exit-status notification.
        send_channel_notice(
            &mut server_writer,
            &crate::session::ExitStatusChannelNotice {
                payload: ExitStatusRequest {
                    exit_status: VarInt::from(42u32),
                },
            },
        )
        .await
        .unwrap();
        write_channel_close(&mut server_writer).await.unwrap();

        let mut session = ClientSession::new(client_reader, client_writer);

        match session.recv_event().await.unwrap().unwrap() {
            SessionEvent::ExitStatus(code) => assert_eq!(code, 42),
            other => panic!("expected ExitStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn eof_returns_none() {
        let (client, server) = channel_pair();
        let (client_reader, client_writer) = tokio::io::split(client);

        // Drop server side to cause EOF.
        drop(server);

        let mut session = ClientSession::new(client_reader, client_writer);
        assert!(session.recv_event().await.unwrap().is_none());
    }
}
