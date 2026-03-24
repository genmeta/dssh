//! Reverse forwarding: bind listeners that open SSH3 channels back to the
//! client for each accepted connection.
//!
//! Provides [`Conversation::bind_tcp_forward`] and
//! [`Conversation::bind_unix_forward`], each returning a listener object
//! whose [`run()`](TcpForwardListener::run) method drives the accept loop.
//! The caller decides when and how to spawn the listener (e.g. via
//! `tokio::spawn`), keeping task lifetime management explicit.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::{ChannelOpen, Conversation, ManageSessionStream},
    forward::{ForwardError, ForwardedStreamlocal, ForwardedTcpip, relay},
};
use h3x::codec::EncodeInto;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, ToSocketAddrs, UnixListener};
use tracing::Instrument;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum ReverseForwardError {
    #[snafu(display("failed to bind TCP listener"))]
    TcpBind { source: std::io::Error },

    #[snafu(display("failed to get local address of TCP listener"))]
    LocalAddr { source: std::io::Error },

    #[snafu(display("failed to bind Unix listener"))]
    UnixBind { source: std::io::Error },
}

// ---------------------------------------------------------------------------
// TCP forward listener
// ---------------------------------------------------------------------------

/// A bound TCP listener ready to accept connections for reverse forwarding.
///
/// Created by [`Conversation::bind_tcp_forward`]. Call [`run()`](Self::run)
/// to enter the accept loop (a long-running async function).
pub struct TcpForwardListener<M: ManageSessionStream, R, W> {
    listener: TcpListener,
    conversation: Arc<Conversation<M, R, W>>,
    bound_addr: std::net::SocketAddr,
}

impl<M: ManageSessionStream, R, W> TcpForwardListener<M, R, W> {
    /// The actual port the listener is bound to.
    pub fn port(&self) -> u16 {
        self.bound_addr.port()
    }
}

impl<M: ManageSessionStream + 'static, R, W> TcpForwardListener<M, R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    /// Run the accept loop, opening a `forwarded-tcpip` channel for each
    /// accepted connection and relaying data bidirectionally.
    ///
    /// This function runs until the listener encounters an accept error.
    /// Cancel the enclosing task to stop the listener.
    pub async fn run(self) {
        tcp_accept_loop(self.listener, self.conversation, self.bound_addr).await;
    }
}

// ---------------------------------------------------------------------------
// Unix forward listener
// ---------------------------------------------------------------------------

/// A bound Unix socket listener ready to accept connections for reverse
/// forwarding.
///
/// Created by [`Conversation::bind_unix_forward`]. Call [`run()`](Self::run)
/// to enter the accept loop. The socket file is automatically removed when
/// the listener is dropped or the task is cancelled.
pub struct UnixForwardListener<M: ManageSessionStream, R, W> {
    listener: UnixListener,
    conversation: Arc<Conversation<M, R, W>>,
    socket_path: UnixSocketGuard,
}

impl<M: ManageSessionStream + 'static, R, W> UnixForwardListener<M, R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    /// Run the accept loop, opening a `forwarded-streamlocal` channel for
    /// each accepted connection and relaying data bidirectionally.
    ///
    /// This function runs until the listener encounters an accept error.
    /// Cancel the enclosing task to stop the listener. The socket file is
    /// removed when this future is dropped (including on cancellation).
    pub async fn run(self) {
        unix_accept_loop(self.listener, self.conversation, &self.socket_path.0).await;
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
// Conversation bind methods
// ---------------------------------------------------------------------------

impl<M: ManageSessionStream + 'static, R, W> Conversation<M, R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    /// Bind a TCP reverse forwarding listener.
    ///
    /// Returns a [`TcpForwardListener`] whose [`port()`](TcpForwardListener::port)
    /// gives the actual bound port. Call [`run()`](TcpForwardListener::run)
    /// (typically inside a spawned task) to start accepting connections.
    pub async fn bind_tcp_forward(
        self: &Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<TcpForwardListener<M, R, W>, ReverseForwardError> {
        let listener = TcpListener::bind(addr)
            .await
            .context(reverse_forward_error::TcpBindSnafu)?;
        let bound_addr = listener
            .local_addr()
            .context(reverse_forward_error::LocalAddrSnafu)?;

        Ok(TcpForwardListener {
            listener,
            conversation: Arc::clone(self),
            bound_addr,
        })
    }

    /// Bind a Unix socket reverse forwarding listener.
    ///
    /// Returns a [`UnixForwardListener`] that removes the socket file when
    /// dropped. Call [`run()`](UnixForwardListener::run) (typically inside a
    /// spawned task) to start accepting connections.
    pub async fn bind_unix_forward(
        self: &Arc<Self>,
        path: impl AsRef<Path>,
    ) -> Result<UnixForwardListener<M, R, W>, ReverseForwardError> {
        let path = path.as_ref();
        let listener = UnixListener::bind(path)
            .context(reverse_forward_error::UnixBindSnafu)?;

        Ok(UnixForwardListener {
            listener,
            conversation: Arc::clone(self),
            socket_path: UnixSocketGuard(path.to_path_buf()),
        })
    }
}

/// Open a reverse-forwarding channel and relay data bidirectionally.
///
/// On failure to open, logs a warning and returns silently.
async fn open_and_relay<M, R, W, C, S>(
    conversation: &Conversation<M, R, W>,
    channel_open: C,
    local_stream: S,
) where
    M: ManageSessionStream + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
    C: ChannelOpen,
    for<'w> C: EncodeInto<&'w mut M::StreamWriter, Output = (), Error = ForwardError>,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (reader, writer) = match conversation
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
        tracing::warn!(error = %e, "reverse relay task panicked");
    }
    if let Err(e) = r2 {
        tracing::warn!(error = %e, "reverse relay task panicked");
    }
}

async fn tcp_accept_loop<M, R, W>(
    listener: TcpListener,
    conversation: Arc<Conversation<M, R, W>>,
    bound_addr: std::net::SocketAddr,
) where
    M: ManageSessionStream + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    let connected_port = bound_addr.port();
    let connected_addr = bound_addr.ip().to_string();

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
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

        tokio::spawn(
            async move {
                let channel_open = ForwardedTcpip {
                    connected_address: connected_addr.into(),
                    connected_port: (connected_port as u32).into(),
                    originator_address: peer_addr.ip().to_string().into(),
                    originator_port: (peer_addr.port() as u32).into(),
                };
                open_and_relay(&conversation, channel_open, tcp_stream).await;
            }
            .in_current_span(),
        );
    }
}

async fn unix_accept_loop<M, R, W>(
    listener: UnixListener,
    conversation: Arc<Conversation<M, R, W>>,
    socket_path: &Path,
) where
    M: ManageSessionStream + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    loop {
        let (unix_stream, _) = match listener.accept().await {
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

        tokio::spawn(
            async move {
                let channel_open = ForwardedStreamlocal {
                    socket_path: path.into(),
                };
                open_and_relay(&conversation, channel_open, unix_stream).await;
            }
            .in_current_span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::stream_id::StreamId;
    use h3x::varint::VarInt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{DuplexStream, duplex};
    use tokio::sync::Mutex as AsyncMutex;

    struct MockStreamState {
        pairs: AsyncMutex<Vec<(DuplexStream, DuplexStream)>>,
        open_called: AtomicBool,
    }

    impl MockStreamState {
        fn new() -> Self {
            Self {
                pairs: AsyncMutex::new(Vec::new()),
                open_called: AtomicBool::new(false),
            }
        }

        async fn provide_pair(&self, reader: DuplexStream, writer: DuplexStream) {
            self.pairs.lock().await.push((reader, writer));
        }
    }

    impl ManageSessionStream for MockStreamState {
        type StreamReader = DuplexStream;
        type StreamWriter = DuplexStream;
        type Error = std::io::Error;

        async fn open_stream(&self) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            self.open_called.store(true, Ordering::SeqCst);
            self.pairs
                .lock()
                .await
                .pop()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no pairs enqueued"))
        }

        async fn accept_stream(&self) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            std::future::pending().await
        }
    }

    struct ArcMock(Arc<MockStreamState>);

    impl ManageSessionStream for ArcMock {
        type StreamReader = DuplexStream;
        type StreamWriter = DuplexStream;
        type Error = std::io::Error;

        async fn open_stream(&self) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            self.0.open_stream().await
        }

        async fn accept_stream(&self) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            self.0.accept_stream().await
        }
    }

    fn make_conversation(mock: Arc<MockStreamState>) -> Arc<Conversation<ArcMock, tokio::io::Empty, tokio::io::Sink>> {
        Arc::new(Conversation::new(
            StreamId(VarInt::from_u32(1)),
            "test",
            tokio::io::empty(),
            tokio::io::sink(),
            ArcMock(mock),
        ))
    }

    #[tokio::test]
    async fn tcp_forward_bind_and_cancel() {
        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let listener = conv.bind_tcp_forward("127.0.0.1:0").await.unwrap();
        assert_ne!(listener.port(), 0, "should get a real port");

        let handle = tokio::spawn(listener.run());
        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn tcp_connection_triggers_open_channel() {
        use h3x::codec::DecodeExt;
        use tokio::io::AsyncWriteExt;

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let listener = conv.bind_tcp_forward("127.0.0.1:0").await.unwrap();
        let port = listener.port();
        let handle = tokio::spawn(listener.run());

        let (local_rd, remote_wr) = duplex(8192);
        let (remote_rd, local_wr) = duplex(8192);
        mock.provide_pair(local_rd, local_wr).await;

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tcp.write_all(b"hello").await.unwrap();

        let mut remote_rd = remote_rd;
        let mut remote_wr = remote_wr;

        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_port: VarInt = remote_rd.decode_one().await.unwrap();
        let _orig_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _orig_port: VarInt = remote_rd.decode_one().await.unwrap();

        use h3x::codec::EncodeExt;
        remote_wr.encode_one(VarInt::from_u32(0)).await.unwrap();
        remote_wr
            .encode_one(VarInt::from_u32(32768))
            .await
            .unwrap();
        remote_wr.flush().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            mock.open_called.load(Ordering::SeqCst),
            "should have called open_stream via Conversation::open_channel"
        );

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn unix_forward_bind_and_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let listener = conv.bind_unix_forward(&sock_path).await.unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        let sock_path_clone = sock_path.clone();
        let handle = tokio::spawn(listener.run());

        // Abort the task — the UnixSocketGuard should clean up the file.
        handle.abort();
        let _ = handle.await;

        // Give a moment for cleanup.
        tokio::task::yield_now().await;
        assert!(!sock_path_clone.exists(), "socket file should be cleaned up on cancel");
    }

    #[tokio::test]
    async fn drop_cleans_up_unix() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("drop-test.sock");

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let listener = conv.bind_unix_forward(&sock_path).await.unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        // Spawn and immediately abort — the guard inside run() cleans up.
        let handle = tokio::spawn(listener.run());
        handle.abort();
        let _ = handle.await;

        tokio::task::yield_now().await;
        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
