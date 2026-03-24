//! Reverse forwarding: bind listeners that open SSH3 channels back to the
//! client for each accepted connection.
//!
//! Provides [`Conversation::run_tcp_forward`] and
//! [`Conversation::run_unix_forward`], which bind a listener and return a
//! future driving the accept loop. The caller decides when and how to spawn
//! the future (e.g. via `tokio::spawn`), keeping task lifetime management
//! explicit.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
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

/// Guard that removes a Unix socket file on drop.
struct UnixSocketGuard(PathBuf);

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl<M: ManageSessionStream + 'static, R, W> Conversation<M, R, W>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    /// Open a channel for reverse forwarding and relay `local_stream` through it.
    ///
    /// On failure to open the channel, logs a warning and returns silently.
    async fn open_channel_and_relay<C, S>(&self, channel_open: C, local_stream: S)
    where
        C: ChannelOpen,
        for<'w> C: EncodeInto<&'w mut M::StreamWriter, Output = (), Error = ForwardError>,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
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
            tracing::warn!(error = %e, "reverse relay task panicked");
        }
        if let Err(e) = r2 {
            tracing::warn!(error = %e, "reverse relay task panicked");
        }
    }

    /// Bind a TCP listener for reverse forwarding.
    ///
    /// Returns `(bound_port, accept_loop)`. Spawn the accept loop (e.g. via
    /// `tokio::spawn`) to start accepting connections. Each accepted
    /// connection opens a `forwarded-tcpip` channel and relays data
    /// bidirectionally.
    pub async fn run_tcp_forward(
        self: &Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<(u16, Pin<Box<dyn Future<Output = ()> + Send>>), ReverseForwardError> {
        let listener = TcpListener::bind(addr)
            .await
            .context(reverse_forward_error::TcpBindSnafu)?;
        let bound_addr = listener
            .local_addr()
            .context(reverse_forward_error::LocalAddrSnafu)?;
        let conversation = Arc::clone(self);

        let accept_loop = async move {
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
                        conversation
                            .open_channel_and_relay(channel_open, tcp_stream)
                            .await;
                    }
                    .in_current_span(),
                );
            }
        };

        Ok((bound_addr.port(), Box::pin(accept_loop)))
    }

    /// Bind a Unix socket for reverse forwarding.
    ///
    /// Returns the accept loop future. The socket file is automatically
    /// removed when the future is dropped (including on cancellation). Spawn
    /// the future to start accepting connections.
    pub async fn run_unix_forward(
        self: &Arc<Self>,
        path: impl AsRef<Path>,
    ) -> Result<Pin<Box<dyn Future<Output = ()> + Send>>, ReverseForwardError> {
        let path = path.as_ref();
        let listener = UnixListener::bind(path)
            .context(reverse_forward_error::UnixBindSnafu)?;
        let guard = UnixSocketGuard(path.to_path_buf());
        let conversation = Arc::clone(self);

        let accept_loop = async move {
            let _guard = guard;
            let socket_path = &_guard.0;

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
                        conversation
                            .open_channel_and_relay(channel_open, unix_stream)
                            .await;
                    }
                    .in_current_span(),
                );
            }
        };

        Ok(Box::pin(accept_loop))
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
                .ok_or_else(|| std::io::Error::other("no pairs enqueued"))
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

        let (port, accept_loop) = conv.run_tcp_forward("127.0.0.1:0").await.unwrap();
        assert_ne!(port, 0, "should get a real port");

        let handle = tokio::spawn(accept_loop);
        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn tcp_connection_triggers_open_channel() {
        use h3x::codec::DecodeExt;
        use tokio::io::AsyncWriteExt;

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let (port, accept_loop) = conv.run_tcp_forward("127.0.0.1:0").await.unwrap();
        let handle = tokio::spawn(accept_loop);

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

        let accept_loop = conv.run_unix_forward(&sock_path).await.unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        let sock_path_clone = sock_path.clone();
        let handle = tokio::spawn(accept_loop);

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

        let accept_loop = conv.run_unix_forward(&sock_path).await.unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        // Spawn and immediately abort — the guard inside the future cleans up.
        let handle = tokio::spawn(accept_loop);
        handle.abort();
        let _ = handle.await;

        tokio::task::yield_now().await;
        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
