//! Reverse forwarding listener management.
//!
//! When a client sends `tcpip-forward` or `streamlocal-forward@openssh.com`
//! global requests, the server starts listeners. For each accepted connection,
//! a new SSH3 channel is opened back to the client via
//! [`Conversation::open_channel`] and raw bytes are relayed.
//!
//! The [`ReverseForwarder`] manages the lifecycle of all active listeners for
//! a single conversation.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::{Conversation, ManageSessionStream},
    forward::{
        ForwardedStreamlocalChannelOpen, ForwardedStreamlocalRequest,
        ForwardedTcpipChannelOpen, ForwardedTcpipRequest,
    },
    forward_runtime::relay,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinHandle;
use tracing::Instrument;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum ReverseForwardError {
    #[snafu(display("failed to bind TCP listener on {addr}:{port}"))]
    TcpBind {
        addr: String,
        port: u16,
        source: std::io::Error,
    },

    #[snafu(display("failed to bind Unix listener on {path}"))]
    UnixBind {
        path: String,
        source: std::io::Error,
    },
}

struct ListenerHandle {
    handle: JoinHandle<()>,
}

impl ListenerHandle {
    fn abort_and_forget(self) {
        self.handle.abort();
    }
}

struct UnixListenerHandle {
    handle: JoinHandle<()>,
    socket_path: String,
}

impl UnixListenerHandle {
    fn abort_and_cleanup(self) {
        self.handle.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Manages reverse forwarding listeners for a single conversation.
///
/// Generic over `M: ManageSessionStream` to work with any transport
/// implementation (direct QUIC, remoc RPC, etc.).
pub struct ReverseForwarder<M: ManageSessionStream + 'static> {
    conversation: Arc<Conversation<M>>,
    tcp_listeners: HashMap<(String, u16), ListenerHandle>,
    unix_listeners: HashMap<String, UnixListenerHandle>,
}

impl<M: ManageSessionStream + 'static> ReverseForwarder<M>
where
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    pub fn new(conversation: Arc<Conversation<M>>) -> Self {
        Self {
            conversation,
            tcp_listeners: HashMap::new(),
            unix_listeners: HashMap::new(),
        }
    }

    /// Start a TCP reverse forwarding listener.
    ///
    /// Binds to `bind_addr:bind_port` (port 0 = OS-assigned) and returns
    /// the actual bound port. Each accepted connection opens a
    /// `forwarded-tcpip` channel via [`Conversation::open_channel`].
    pub async fn start_tcp(
        &mut self,
        bind_addr: &str,
        bind_port: u16,
    ) -> Result<u16, ReverseForwardError> {
        let listener = TcpListener::bind((bind_addr, bind_port))
            .await
            .context(reverse_forward_error::TcpBindSnafu {
                addr: bind_addr,
                port: bind_port,
            })?;
        let actual_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(bind_port);

        let conversation = Arc::clone(&self.conversation);
        let bind_addr_owned = bind_addr.to_owned();

        let handle = tokio::spawn(
            async move {
                tcp_accept_loop(listener, conversation, &bind_addr_owned).await;
            }
            .in_current_span(),
        );

        if let Some(old) = self
            .tcp_listeners
            .insert((bind_addr.to_owned(), actual_port), ListenerHandle { handle })
        {
            old.abort_and_forget();
        }

        Ok(actual_port)
    }

    /// Stop a TCP reverse forwarding listener. Returns `true` if found.
    pub fn stop_tcp(&mut self, bind_addr: &str, bind_port: u16) -> bool {
        if let Some(handle) = self
            .tcp_listeners
            .remove(&(bind_addr.to_owned(), bind_port))
        {
            handle.abort_and_forget();
            true
        } else {
            false
        }
    }

    /// Start a Unix socket reverse forwarding listener.
    pub async fn start_unix(&mut self, socket_path: &str) -> Result<(), ReverseForwardError> {
        let listener =
            UnixListener::bind(socket_path).map_err(|source| ReverseForwardError::UnixBind {
                path: socket_path.to_owned(),
                source,
            })?;

        let conversation = Arc::clone(&self.conversation);
        let path_owned = socket_path.to_owned();

        let handle = tokio::spawn(
            async move {
                unix_accept_loop(listener, conversation, &path_owned).await;
            }
            .in_current_span(),
        );

        if let Some(old) = self.unix_listeners.insert(
            socket_path.to_owned(),
            UnixListenerHandle {
                handle,
                socket_path: socket_path.to_owned(),
            },
        ) {
            old.abort_and_cleanup();
        }

        Ok(())
    }

    /// Stop a Unix socket reverse forwarding listener. Returns `true` if found.
    pub fn stop_unix(&mut self, socket_path: &str) -> bool {
        if let Some(handle) = self.unix_listeners.remove(socket_path) {
            handle.abort_and_cleanup();
            true
        } else {
            false
        }
    }

    /// Shut down all active listeners.
    pub fn shutdown(mut self) {
        for (_, handle) in self.tcp_listeners.drain() {
            handle.abort_and_forget();
        }
        for (_, handle) in self.unix_listeners.drain() {
            handle.abort_and_cleanup();
        }
    }
}

impl<M: ManageSessionStream + 'static> Drop for ReverseForwarder<M>
where
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    fn drop(&mut self) {
        for (_, handle) in self.tcp_listeners.drain() {
            handle.abort_and_forget();
        }
        for (_, handle) in self.unix_listeners.drain() {
            handle.abort_and_cleanup();
        }
    }
}

async fn tcp_accept_loop<M>(
    listener: TcpListener,
    conversation: Arc<Conversation<M>>,
    bind_addr: &str,
) where
    M: ManageSessionStream + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    let connected_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

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
        let connected_addr = bind_addr.to_owned();
        let originator_addr = peer_addr.ip().to_string();
        let originator_port = peer_addr.port();

        tokio::spawn(
            async move {
                let channel_open = ForwardedTcpipChannelOpen {
                    payload: ForwardedTcpipRequest {
                        connected_address: connected_addr.into(),
                        connected_port: (connected_port as u32).into(),
                        originator_address: originator_addr.into(),
                        originator_port: (originator_port as u32).into(),
                    },
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
                let ch2s = tokio::spawn(relay(reader, tcp_writer));
                let s2ch = tokio::spawn(relay(tcp_reader, writer));
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
    socket_path: &str,
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
        let path = socket_path.to_owned();

        tokio::spawn(
            async move {
                let channel_open = ForwardedStreamlocalChannelOpen {
                    payload: ForwardedStreamlocalRequest {
                        socket_path: path.into(),
                    },
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
                let ch2s = tokio::spawn(relay(reader, unix_writer));
                let s2ch = tokio::spawn(relay(unix_reader, writer));
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{duplex, DuplexStream};
    use tokio::sync::Mutex as AsyncMutex;
    use h3x::stream_id::StreamId;
    use h3x::varint::VarInt;

    // -- Mock ManageSessionStream using DuplexStream pairs ------------------

    /// Internal state shared between the mock and the test.
    struct MockStreamState {
        /// Pre-queued (local_reader, local_writer) pairs for open_stream().
        /// The test holds the matching remote ends.
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

        /// Enqueue a pair that the next `open_stream()` call will return.
        async fn provide_pair(&self, reader: DuplexStream, writer: DuplexStream) {
            self.pairs.lock().await.push((reader, writer));
        }
    }

    impl ManageSessionStream for MockStreamState {
        type StreamReader = DuplexStream;
        type StreamWriter = DuplexStream;
        type Error = std::io::Error;

        async fn open_stream(
            &self,
        ) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            self.open_called.store(true, Ordering::SeqCst);
            self.pairs
                .lock()
                .await
                .pop()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "no pairs enqueued")
                })
        }

        async fn accept_stream(
            &self,
        ) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            // Not used in reverse forwarder; pend forever.
            std::future::pending().await
        }
    }

    /// Thin newtype so we can pass `Arc<MockStreamState>` into
    /// `Conversation::new()` (which takes M by value) while retaining
    /// an Arc clone for the test to interact with.
    struct ArcMock(Arc<MockStreamState>);

    impl ManageSessionStream for ArcMock {
        type StreamReader = DuplexStream;
        type StreamWriter = DuplexStream;
        type Error = std::io::Error;

        async fn open_stream(
            &self,
        ) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            self.0.open_stream().await
        }

        async fn accept_stream(
            &self,
        ) -> Result<(DuplexStream, DuplexStream), std::io::Error> {
            self.0.accept_stream().await
        }
    }

    /// Create a Conversation backed by `ArcMock`, returning both the
    /// `Arc<Conversation>` and the shared mock state for the test to
    /// enqueue stream pairs.
    fn make_forwarder_conversation(
        mock: Arc<MockStreamState>,
    ) -> Arc<Conversation<ArcMock>> {
        Arc::new(Conversation::new(
            StreamId(VarInt::from_u32(1)),
            "test",
            tokio::io::empty(),
            tokio::io::sink(),
            ArcMock(mock),
        ))
    }

    // -- Tests --------------------------------------------------------------

    #[tokio::test]
    async fn tcp_start_and_stop() {
        let mock = Arc::new(MockStreamState::new());
        let conv = make_forwarder_conversation(Arc::clone(&mock));
        let mut forwarder = ReverseForwarder::new(conv);

        let port = forwarder.start_tcp("127.0.0.1", 0).await.unwrap();
        assert_ne!(port, 0, "should get a real port");

        assert!(forwarder.stop_tcp("127.0.0.1", port));
        assert!(!forwarder.stop_tcp("127.0.0.1", port), "double stop returns false");
    }

    #[tokio::test]
    async fn tcp_connection_triggers_open_channel() {
        use h3x::codec::DecodeExt;
        use tokio::io::AsyncWriteExt;

        let mock = Arc::new(MockStreamState::new());
        let conv = make_forwarder_conversation(Arc::clone(&mock));
        let mut forwarder = ReverseForwarder::new(Arc::clone(&conv));

        let port = forwarder.start_tcp("127.0.0.1", 0).await.unwrap();

        // Prepare a stream pair: Conversation gets (local_rd, local_wr),
        // we keep (remote_rd, remote_wr) to simulate the remote peer.
        let (local_rd, remote_wr) = duplex(8192);
        let (remote_rd, local_wr) = duplex(8192);
        mock.provide_pair(local_rd, local_wr).await;

        // Connect to trigger the accept loop → open_channel().
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tcp.write_all(b"hello").await.unwrap();

        // On the "remote" side, read the channel open header that
        // Conversation::open_channel wrote, then send confirmation.
        let mut remote_rd = remote_rd;
        let mut remote_wr = remote_wr;

        // open_channel writes: max_message_size (VarInt) + channel_type (SshString) + payload.
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        // ForwardedTcpipRequest payload: connected_address, connected_port,
        // originator_address, originator_port.
        let _connected_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_port: VarInt = remote_rd.decode_one().await.unwrap();
        let _orig_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _orig_port: VarInt = remote_rd.decode_one().await.unwrap();

        // Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION (VarInt 0) + max_message_size.
        use h3x::codec::EncodeExt;
        remote_wr.encode_one(VarInt::from_u32(0)).await.unwrap(); // confirmation
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap(); // max_msg_size
        remote_wr.flush().await.unwrap();

        // Give the relay a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            mock.open_called.load(Ordering::SeqCst),
            "should have called open_stream via Conversation::open_channel"
        );

        forwarder.shutdown();
    }

    #[tokio::test]
    async fn unix_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let sock_str = sock_path.to_str().unwrap();

        let mock = Arc::new(MockStreamState::new());
        let conv = make_forwarder_conversation(Arc::clone(&mock));
        let mut forwarder = ReverseForwarder::new(conv);

        forwarder.start_unix(sock_str).await.unwrap();
        assert!(sock_path.exists(), "socket file should exist");

        assert!(forwarder.stop_unix(sock_str));
        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up"
        );
    }

    #[tokio::test]
    async fn drop_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("drop-test.sock");
        let sock_str = sock_path.to_str().unwrap();

        let mock = Arc::new(MockStreamState::new());
        let conv = make_forwarder_conversation(Arc::clone(&mock));
        let mut forwarder = ReverseForwarder::new(conv);

        let _port = forwarder.start_tcp("127.0.0.1", 0).await.unwrap();
        forwarder.start_unix(sock_str).await.unwrap();

        drop(forwarder);

        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
