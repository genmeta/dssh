//! Reverse forwarding: bind listeners that open SSH3 channels back to the
//! client for each accepted connection.
//!
//! Use [`DecodedGlobalRequest::accept_tcp_forward`] and
//! [`DecodedGlobalRequest::accept_unix_forward`] to accept a forwarding
//! request (bind listener + respond to remote). The returned listener
//! struct has a [`run`](TcpForwardListener::run) method that drives the
//! accept loop.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::global::{DecodedGlobalRequest, RespondSuccessError},
    conversation::{ChannelOpen, Conversation},
    forward::{
        ForwardError, ForwardedStreamlocal, ForwardedTcpip, StreamlocalForwardRequest,
        TcpipForwardReply, TcpipForwardRequest, relay,
    },
};
use h3x::codec::EncodeInto;
use h3x::varint::VarInt;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinSet;
use tracing::Instrument;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum AcceptTcpForwardError {
    #[snafu(display("bind port overflows u16"))]
    PortOverflow,

    #[snafu(display("failed to bind TCP listener"))]
    TcpBind { source: std::io::Error },

    #[snafu(display("failed to get local address of TCP listener"))]
    LocalAddr { source: std::io::Error },

    #[snafu(display("failed to send success response"))]
    Respond {
        source: RespondSuccessError<ForwardError>,
    },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum AcceptUnixForwardError {
    #[snafu(display("failed to bind Unix listener"))]
    UnixBind { source: std::io::Error },

    #[snafu(display("failed to send success response"))]
    Respond {
        source: RespondSuccessError<std::convert::Infallible>,
    },
}

// ---------------------------------------------------------------------------
// TCP forward listener
// ---------------------------------------------------------------------------

/// A bound TCP listener ready to accept reverse-forwarded connections.
///
/// Obtained from [`DecodedGlobalRequest::accept_tcp_forward`].
pub struct TcpForwardListener {
    listener: TcpListener,
    bound_addr: SocketAddr,
}

impl TcpForwardListener {
    /// Bind a TCP listener at the given address.
    pub async fn bind(addr: impl tokio::net::ToSocketAddrs) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            bound_addr,
        })
    }

    /// The address the listener is bound to.
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Run the accept loop, opening a `forwarded-tcpip` channel for each
    /// accepted connection and relaying data bidirectionally.
    ///
    /// Runs until the listener encounters an accept error. Cancel the
    /// enclosing task to stop the listener.
    pub async fn run<S>(self, conversation: Arc<Conversation<S>>)
    where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
    {
        let connected_port = self.bound_addr.port();
        let connected_addr = self.bound_addr.ip().to_string();
        let mut tasks = JoinSet::new();

        loop {
            let (tcp_stream, peer_addr) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(
                        error = %snafu::Report::from_error(&e),
                        "reverse-tcp accept error, stopping listener"
                    );
                    break;
                }
            };

            let conversation = Arc::clone(&conversation);
            let connected_addr = connected_addr.clone();

            tasks.spawn(
                async move {
                    let channel_open = ForwardedTcpip {
                        connected_address: connected_addr.into(),
                        connected_port: (connected_port as u32).into(),
                        originator_address: peer_addr.ip().to_string().into(),
                        originator_port: (peer_addr.port() as u32).into(),
                    };
                    conversation
                        .open_channel_and_relay(channel_open, tcp_stream)
                        .await;
                }
                .in_current_span(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Unix forward listener
// ---------------------------------------------------------------------------

/// A bound Unix socket listener ready to accept reverse-forwarded connections.
///
/// Obtained from [`DecodedGlobalRequest::accept_unix_forward`].
/// The socket file is automatically removed when this value is dropped.
pub struct UnixForwardListener {
    listener: UnixListener,
    guard: UnixSocketGuard,
}

impl UnixForwardListener {
    /// Bind a Unix socket at the given path.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let path = path.as_ref();
        let listener = UnixListener::bind(path)?;
        Ok(Self {
            listener,
            guard: UnixSocketGuard(path.to_path_buf()),
        })
    }

    /// Run the accept loop, opening a `forwarded-streamlocal` channel for
    /// each accepted connection and relaying data bidirectionally.
    ///
    /// Runs until the listener encounters an accept error. Cancel the
    /// enclosing task to stop the listener. The socket file is removed
    /// when this future is dropped (including on cancellation).
    pub async fn run<S>(self, conversation: Arc<Conversation<S>>)
    where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
    {
        let _guard = self.guard;
        let socket_path = &_guard.0;
        let mut tasks = JoinSet::new();

        loop {
            let (unix_stream, _) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(
                        error = %snafu::Report::from_error(&e),
                        "reverse-streamlocal accept error, stopping listener"
                    );
                    break;
                }
            };

            let conversation = Arc::clone(&conversation);
            let path = socket_path.display().to_string();

            tasks.spawn(
                async move {
                    let channel_open = ForwardedStreamlocal {
                        socket_path: path.into(),
                    };
                    conversation
                        .open_channel_and_relay(channel_open, unix_stream)
                        .await;
                }
                .in_current_span(),
            );
        }
    }
}

/// Guard that removes a Unix socket file on drop.
struct UnixSocketGuard(PathBuf);

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------
// DecodedGlobalRequest methods for accepting forward requests
// ---------------------------------------------------------------------------

impl<R, W> DecodedGlobalRequest<TcpipForwardRequest, R, W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Accept a `tcpip-forward` request: bind a TCP listener, respond with
    /// the allocated port, and return the listener.
    ///
    /// On bind failure, responds with failure automatically.
    pub async fn accept_tcp_forward(self) -> Result<TcpForwardListener, AcceptTcpForwardError> {
        use accept_tcp_forward_error::*;

        let bind_address = self.payload().bind_address.to_string();
        // Empty or wildcard bind address means "all interfaces" (OpenSSH convention).
        let bind_addr = match bind_address.as_str() {
            "" | "*" => "0.0.0.0",
            other => other,
        };
        let bind_port = u16::try_from(self.payload().bind_port.into_inner())
            .map_err(|_| AcceptTcpForwardError::PortOverflow)?;

        let listener = match TcpListener::bind((bind_addr, bind_port)).await {
            Ok(l) => l,
            Err(source) => {
                let _ = self.respond_failure().await;
                return Err(AcceptTcpForwardError::TcpBind { source });
            }
        };
        let bound_addr = match listener.local_addr() {
            Ok(a) => a,
            Err(source) => {
                let _ = self.respond_failure().await;
                return Err(AcceptTcpForwardError::LocalAddr { source });
            }
        };

        let reply = TcpipForwardReply {
            allocated_port: VarInt::from(bound_addr.port() as u32),
        };
        self.respond_success(reply).await.context(RespondSnafu)?;

        Ok(TcpForwardListener {
            listener,
            bound_addr,
        })
    }
}

impl<R, W> DecodedGlobalRequest<StreamlocalForwardRequest, R, W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Accept a `streamlocal-forward` request: bind a Unix socket, respond
    /// with success, and return the listener.
    ///
    /// On bind failure, responds with failure automatically.
    pub async fn accept_unix_forward(self) -> Result<UnixForwardListener, AcceptUnixForwardError> {
        use accept_unix_forward_error::*;

        let socket_path = self.payload().socket_path.to_string();

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(source) => {
                let _ = self.respond_failure().await;
                return Err(AcceptUnixForwardError::UnixBind { source });
            }
        };

        self.respond_success(crate::conversation::EmptyPayload)
            .await
            .context(RespondSnafu)?;

        Ok(UnixForwardListener {
            listener,
            guard: UnixSocketGuard(PathBuf::from(socket_path)),
        })
    }
}

// ---------------------------------------------------------------------------
// Conversation helper: open channel and relay
// ---------------------------------------------------------------------------

impl<S> Conversation<S>
where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
{
    /// Open a channel for reverse forwarding and relay `local_stream`
    /// through it bidirectionally.
    ///
    /// On failure to open the channel, logs a warning and returns silently.
    pub(crate) async fn open_channel_and_relay<C, T>(&self, channel_open: C, local_stream: T)
    where
        C: ChannelOpen,
        for<'w> C: EncodeInto<
                &'w mut h3x::codec::SinkWriter<S::StreamWriter>,
                Output = (),
                Error = ForwardError,
            >,
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = match self
            .open_channel(&channel_open, DEFAULT_MAX_MESSAGE_SIZE)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %snafu::Report::from_error(&e), "reverse channel open failed");
                return;
            }
        };

        let (local_reader, local_writer) = tokio::io::split(local_stream);
        let ch2s = tokio::spawn(relay(reader, local_writer).in_current_span());
        let s2ch = tokio::spawn(relay(local_reader, writer).in_current_span());
        let (r1, r2) = tokio::join!(ch2s, s2ch);
        if let Err(e) = r1 {
            tracing::warn!(error = %snafu::Report::from_error(&e), "reverse relay task panicked");
        }
        if let Err(e) = r2 {
            tracing::warn!(error = %snafu::Report::from_error(&e), "reverse relay task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{MockWebTransportSession as TestSession, stream_pair as make_half};
    use h3x::{stream_id::StreamId, varint::VarInt};

    fn make_test_session() -> TestSession {
        TestSession::new(StreamId(VarInt::from_u32(40)))
    }

    fn make_conversation(session: TestSession) -> Arc<Conversation<TestSession>> {
        let stream_id = VarInt::from_u32(40);
        let (local_reader, _remote_writer) = make_half(stream_id);
        let (_remote_reader, local_writer) = make_half(stream_id);
        Arc::new(Conversation::from_control_streams(
            session,
            "test",
            local_reader,
            local_writer,
        ))
    }

    #[tokio::test]
    async fn tcp_forward_bind_and_cancel() {
        let conv = make_conversation(make_test_session());

        let listener = TcpForwardListener::bind("127.0.0.1:0").await.unwrap();
        assert_ne!(listener.bound_addr().port(), 0, "should get a real port");

        let handle = tokio::spawn(listener.run(conv));
        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn tcp_connection_triggers_open_channel() {
        use h3x::codec::DecodeExt;
        use tokio::io::AsyncWriteExt;

        let session = make_test_session();
        let conv = make_conversation(session.clone());

        let listener = TcpForwardListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.bound_addr().port();
        let handle = tokio::spawn(listener.run(Arc::clone(&conv)));

        let stream_id = VarInt::from_u32(44);
        let (remote_rd, local_wr) = make_half(stream_id);
        let (local_rd, remote_wr) = make_half(stream_id);
        session.provide_open_stream(local_rd, local_wr);

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tcp.write_all(b"hello").await.unwrap();

        let mut remote_rd = remote_rd;
        let mut remote_wr = remote_wr;

        let stream_kind: VarInt = remote_rd.decode_one().await.unwrap();
        assert_eq!(stream_kind, crate::webtransport::DSSH_CHANNEL_STREAM_KIND);
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_port: VarInt = remote_rd.decode_one().await.unwrap();
        let _orig_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _orig_port: VarInt = remote_rd.decode_one().await.unwrap();

        use h3x::codec::EncodeExt;
        remote_wr.encode_one(VarInt::from_u32(91)).await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap();
        remote_wr.flush().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            session.open_called(),
            "should have called open_stream via Conversation::open_channel"
        );

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn unix_forward_bind_and_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let conv = make_conversation(make_test_session());

        let listener = UnixForwardListener::bind(&sock_path).unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        let sock_path_clone = sock_path.clone();
        let handle = tokio::spawn(listener.run(conv));

        handle.abort();
        let _ = handle.await;

        tokio::task::yield_now().await;
        assert!(
            !sock_path_clone.exists(),
            "socket file should be cleaned up on cancel"
        );
    }

    #[tokio::test]
    async fn drop_cleans_up_unix() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("drop-test.sock");

        let conv = make_conversation(make_test_session());

        let listener = UnixForwardListener::bind(&sock_path).unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        let handle = tokio::spawn(listener.run(conv));
        handle.abort();
        let _ = handle.await;

        tokio::task::yield_now().await;
        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
