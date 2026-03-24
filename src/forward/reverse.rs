//! Reverse forwarding: start listeners that open SSH3 channels back to the
//! client for each accepted connection.
//!
//! Provides [`Conversation::forward_tcp`] and [`Conversation::forward_unix`],
//! each returning a [`ForwardHandle`] that stops the listener on drop.

use std::path::Path;
use std::sync::Arc;

use crate::{
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::{Conversation, ManageSessionStream},
    forward::{
        ForwardedStreamlocal, ForwardedTcpip,
    },
    forward::relay,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, ToSocketAddrs, UnixListener};
use tokio::task::JoinHandle;
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

/// Handle to a single active reverse-forwarding listener.
///
/// Dropping the handle aborts the accept loop and performs cleanup
/// (e.g., removing the Unix socket file).
pub struct ForwardHandle {
    handle: JoinHandle<()>,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl ForwardHandle {
    /// Stop the listener explicitly.
    pub fn stop(mut self) {
        self.handle.abort();
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

impl Drop for ForwardHandle {
    fn drop(&mut self) {
        self.handle.abort();
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

impl<M: ManageSessionStream + 'static> Conversation<M>
where
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    /// Start a TCP reverse forwarding listener.
    ///
    /// Each accepted connection opens a `forwarded-tcpip` channel to the
    /// client and relays data bidirectionally. Returns the actual bound port
    /// and a [`ForwardHandle`] to control the listener's lifetime.
    pub async fn forward_tcp(
        self: &Arc<Self>,
        addr: impl ToSocketAddrs,
    ) -> Result<(u16, ForwardHandle), ReverseForwardError> {
        let listener = TcpListener::bind(addr)
            .await
            .context(reverse_forward_error::TcpBindSnafu)?;
        let local_addr = listener
            .local_addr()
            .context(reverse_forward_error::LocalAddrSnafu)?;

        let conversation = Arc::clone(self);
        let handle = tokio::spawn(
            tcp_accept_loop(listener, conversation, local_addr).in_current_span(),
        );

        Ok((local_addr.port(), ForwardHandle { handle, cleanup: None }))
    }

    /// Start a Unix socket reverse forwarding listener.
    ///
    /// Each accepted connection opens a `forwarded-streamlocal` channel.
    /// The socket file is removed when the handle is stopped or dropped.
    pub async fn forward_unix(
        self: &Arc<Self>,
        path: impl AsRef<Path>,
    ) -> Result<ForwardHandle, ReverseForwardError> {
        let path = path.as_ref();
        let listener = UnixListener::bind(path)
            .context(reverse_forward_error::UnixBindSnafu)?;

        let path_for_task = path.to_path_buf();
        let path_for_cleanup = path.to_path_buf();
        let conversation = Arc::clone(self);

        let handle = tokio::spawn(
            async move {
                unix_accept_loop(listener, conversation, &path_for_task).await;
            }
            .in_current_span(),
        );

        Ok(ForwardHandle {
            handle,
            cleanup: Some(Box::new(move || {
                let _ = std::fs::remove_file(path_for_cleanup);
            })),
        })
    }
}

async fn tcp_accept_loop<M>(
    listener: TcpListener,
    conversation: Arc<Conversation<M>>,
    bound_addr: std::net::SocketAddr,
) where
    M: ManageSessionStream + 'static,
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
        let originator_addr = peer_addr.ip().to_string();
        let originator_port = peer_addr.port();

        tokio::spawn(
            async move {
                let channel_open = ForwardedTcpip {
                    connected_address: connected_addr.into(),
                    connected_port: (connected_port as u32).into(),
                    originator_address: originator_addr.into(),
                    originator_port: (originator_port as u32).into(),
                };
                let (reader, writer) = match conversation
                    .open_channel(&channel_open, DEFAULT_MAX_MESSAGE_SIZE)
                    .await
                {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(
                            error = %snafu::Report::from_error(&e),
                            "forwarded-tcpip open_channel failed"
                        );
                        return;
                    }
                };

                let (tcp_reader, tcp_writer) = tokio::io::split(tcp_stream);
                let ch2s = tokio::spawn(relay(reader, tcp_writer).in_current_span());
                let s2ch = tokio::spawn(relay(tcp_reader, writer).in_current_span());
                let (r1, r2) = tokio::join!(ch2s, s2ch);
                if let Err(e) = r1 {
                    tracing::warn!(error = %e, "forwarded-tcpip relay task panicked");
                }
                if let Err(e) = r2 {
                    tracing::warn!(error = %e, "forwarded-tcpip relay task panicked");
                }
            }
            .in_current_span(),
        );
    }
}

async fn unix_accept_loop<M>(
    listener: UnixListener,
    conversation: Arc<Conversation<M>>,
    socket_path: &Path,
) where
    M: ManageSessionStream + 'static,
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
                let (reader, writer) = match conversation
                    .open_channel(&channel_open, DEFAULT_MAX_MESSAGE_SIZE)
                    .await
                {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(
                            error = %snafu::Report::from_error(&e),
                            "forwarded-streamlocal open_channel failed"
                        );
                        return;
                    }
                };

                let (unix_reader, unix_writer) = tokio::io::split(unix_stream);
                let ch2s = tokio::spawn(relay(reader, unix_writer).in_current_span());
                let s2ch = tokio::spawn(relay(unix_reader, writer).in_current_span());
                let (r1, r2) = tokio::join!(ch2s, s2ch);
                if let Err(e) = r1 {
                    tracing::warn!(error = %e, "forwarded-streamlocal relay task panicked");
                }
                if let Err(e) = r2 {
                    tracing::warn!(error = %e, "forwarded-streamlocal relay task panicked");
                }
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

    fn make_conversation(mock: Arc<MockStreamState>) -> Arc<Conversation<ArcMock>> {
        Arc::new(Conversation::new(
            StreamId(VarInt::from_u32(1)),
            "test",
            tokio::io::empty(),
            tokio::io::sink(),
            ArcMock(mock),
        ))
    }

    #[tokio::test]
    async fn tcp_forward_and_stop() {
        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let (port, handle) = conv.forward_tcp("127.0.0.1:0").await.unwrap();
        assert_ne!(port, 0, "should get a real port");
        handle.stop();
    }

    #[tokio::test]
    async fn tcp_connection_triggers_open_channel() {
        use h3x::codec::DecodeExt;
        use tokio::io::AsyncWriteExt;

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let (port, handle) = conv.forward_tcp("127.0.0.1:0").await.unwrap();

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

        handle.stop();
    }

    #[tokio::test]
    async fn unix_forward_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let handle = conv.forward_unix(&sock_path).await.unwrap();
        assert!(sock_path.exists(), "socket file should exist");

        handle.stop();
        assert!(!sock_path.exists(), "socket file should be cleaned up");
    }

    #[tokio::test]
    async fn drop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("drop-test.sock");

        let mock = Arc::new(MockStreamState::new());
        let conv = make_conversation(Arc::clone(&mock));

        let _tcp = conv.forward_tcp("127.0.0.1:0").await.unwrap();
        let _unix = conv.forward_unix(&sock_path).await.unwrap();

        drop(_unix);
        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
