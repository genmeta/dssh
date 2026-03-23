//! Reverse forwarding listener management.
//!
//! When a client sends `tcpip-forward` or `streamlocal-forward@openssh.com`
//! global requests, the server starts listeners. For each accepted connection,
//! a new SSH3 channel is opened back to the client and raw bytes are relayed.
//!
//! The [`ReverseForwarder`] manages the lifecycle of all active listeners for
//! a single conversation, parameterized over the stream management trait.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::{ManageSessionStream, ChannelOpen},
    forward::{
        ForwardedTcpipChannelOpen, ForwardedTcpipRequest,
        ForwardedStreamlocalChannelOpen, ForwardedStreamlocalRequest,
    },
    forward_runtime::relay,
};
use h3x::codec::EncodeInto;
use snafu::{ResultExt, Snafu};
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
    manage: Arc<M>,
    tcp_listeners: HashMap<(String, u16), ListenerHandle>,
    unix_listeners: HashMap<String, UnixListenerHandle>,
}

impl<M: ManageSessionStream + 'static> ReverseForwarder<M> {
    pub fn new(manage: Arc<M>) -> Self {
        Self {
            manage,
            tcp_listeners: HashMap::new(),
            unix_listeners: HashMap::new(),
        }
    }

    /// Start a TCP reverse forwarding listener.
    ///
    /// Binds to `bind_addr:bind_port` (port 0 = OS-assigned) and returns
    /// the actual bound port. Each accepted connection opens a
    /// `forwarded-tcpip` channel via the stream manager.
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

        let manage = Arc::clone(&self.manage);
        let bind_addr_owned = bind_addr.to_owned();

        let handle = tokio::spawn(
            async move {
                tcp_accept_loop(listener, manage, &bind_addr_owned).await;
            }
            .in_current_span(),
        );

        // If there was a previous listener on this addr:port, abort it.
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

        let manage = Arc::clone(&self.manage);
        let path_owned = socket_path.to_owned();

        let handle = tokio::spawn(
            async move {
                unix_accept_loop(listener, manage, &path_owned).await;
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
        // drain to avoid double-cleanup in Drop
        for (_, handle) in self.tcp_listeners.drain() {
            handle.abort_and_forget();
        }
        for (_, handle) in self.unix_listeners.drain() {
            handle.abort_and_cleanup();
        }
    }
}

impl<M: ManageSessionStream + 'static> Drop for ReverseForwarder<M> {
    fn drop(&mut self) {
        for (_, handle) in self.tcp_listeners.drain() {
            handle.abort_and_forget();
        }
        for (_, handle) in self.unix_listeners.drain() {
            handle.abort_and_cleanup();
        }
    }
}

async fn tcp_accept_loop<M: ManageSessionStream + 'static>(
    listener: TcpListener,
    manage: Arc<M>,
    bind_addr: &str,
) {
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

        let manage = Arc::clone(&manage);
        let connected_addr = bind_addr.to_owned();
        let connected_port = listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(0);
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
                if let Err(e) = open_and_relay_forwarded(manage, &channel_open, tcp_stream).await {
                    tracing::warn!(
                        error = %e,
                        "forwarded-tcpip channel error"
                    );
                }
            }
            .in_current_span(),
        );
    }
}

async fn unix_accept_loop<M: ManageSessionStream + 'static>(
    listener: UnixListener,
    manage: Arc<M>,
    socket_path: &str,
) {
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

        let manage = Arc::clone(&manage);
        let path = socket_path.to_owned();

        tokio::spawn(
            async move {
                let channel_open = ForwardedStreamlocalChannelOpen {
                    payload: ForwardedStreamlocalRequest {
                        socket_path: path.into(),
                    },
                };
                if let Err(e) = open_and_relay_forwarded(manage, &channel_open, unix_stream).await {
                    tracing::warn!(
                        error = %e,
                        "forwarded-streamlocal channel error"
                    );
                }
            }
            .in_current_span(),
        );
    }
}

/// Open a new channel via the stream manager, write the channel open header,
/// wait for confirmation, then relay bytes bidirectionally.
///
/// Uses the same protocol as [`Conversation::open_channel`] — writes
/// `max_message_size + channel_type + payload` (transport framing is handled
/// by [`ManageSessionStream::open_stream`]), reads confirmation, then relays
/// raw bytes.
async fn open_and_relay_forwarded<M, C, PE, S>(
    manage: Arc<M>,
    channel_open: &C,
    stream: S,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    M: ManageSessionStream + 'static,
    C: ChannelOpen,
    PE: std::error::Error + Send + Sync + 'static,
    for<'w> C::Payload: h3x::codec::EncodeInto<&'w mut M::StreamWriter, Output = (), Error = PE>,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    use h3x::codec::EncodeExt;

    let (mut reader, mut writer) = manage
        .open_stream()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

    // Write channel open header (MSS already wrote signal_value + session_id).
    writer
        .encode_one(DEFAULT_MAX_MESSAGE_SIZE)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
    writer
        .encode_one(channel_open.channel_type())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(std::io::Error::other(e)) })?;
    channel_open
        .payload()
        .clone()
        .encode_into(&mut writer)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
    tokio::io::AsyncWriteExt::flush(&mut writer)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

    // Read confirmation.
    crate::conversation::read_channel_open_response(&mut reader)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

    // Relay raw bytes bidirectionally.
    let (stream_reader, stream_writer) = tokio::io::split(stream);
    let ch2s = tokio::spawn(relay(reader, stream_writer));
    let s2ch = tokio::spawn(relay(stream_reader, writer));
    let (r1, r2) = tokio::join!(ch2s, s2ch);
    r1.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
    r2.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::varint::VarInt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{duplex, AsyncWriteExt, DuplexStream};
    use tokio::sync::Mutex;

    /// A mock ManageSessionStream that returns duplex pairs and stores
    /// the "remote" ends for the test to interact with.
    struct MockManage {
        remote_pairs: Mutex<Vec<(DuplexStream, DuplexStream)>>,
        open_called: AtomicBool,
    }

    impl MockManage {
        fn new() -> (Arc<Self>, Arc<Mutex<Vec<(DuplexStream, DuplexStream)>>>) {
            let remote = Arc::new(Mutex::new(Vec::new()));
            let manage = Arc::new(Self {
                remote_pairs: Mutex::new(Vec::new()),
                open_called: AtomicBool::new(false),
            });
            (manage, remote)
        }
    }

    impl ManageSessionStream for MockManage {
        type StreamReader = DuplexStream;
        type StreamWriter = DuplexStream;
        type Error = std::io::Error;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.open_called.store(true, Ordering::SeqCst);
            // Create two duplex pairs: one for the "channel" side, one for the "remote" side
            let (local_rd, remote_wr) = duplex(8192);
            let (remote_rd, local_wr) = duplex(8192);
            self.remote_pairs
                .lock()
                .await
                .push((remote_rd, remote_wr));
            Ok((local_rd, local_wr))
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "not used in reverse forwarder tests",
            ))
        }
    }

    #[tokio::test]
    async fn tcp_start_and_stop() {
        let (manage, _remote) = MockManage::new();
        let mut forwarder = ReverseForwarder::new(manage);

        let port = forwarder.start_tcp("127.0.0.1", 0).await.unwrap();
        assert_ne!(port, 0, "should get a real port");

        // Verify we can connect (listener is active)
        let _tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        assert!(forwarder.stop_tcp("127.0.0.1", port));
        assert!(!forwarder.stop_tcp("127.0.0.1", port), "double stop returns false");
    }

    #[tokio::test]
    async fn tcp_connection_opens_channel() {
        let (manage, _remote) = MockManage::new();
        let mut forwarder = ReverseForwarder::new(Arc::clone(&manage));

        let port = forwarder.start_tcp("127.0.0.1", 0).await.unwrap();

        // Connect to trigger the accept loop
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tcp.write_all(b"test-data").await.unwrap();
        drop(tcp);

        // Wait a bit for the spawned task to open the channel
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            manage.open_called.load(Ordering::SeqCst),
            "should have called open_stream"
        );

        // The remote_pairs should have one entry
        let pairs = manage.remote_pairs.lock().await;
        assert_eq!(pairs.len(), 1, "should have opened one channel");

        forwarder.shutdown();
    }

    #[tokio::test]
    async fn unix_start_and_stop() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let sock_str = sock_path.to_str().unwrap();

        let (manage, _remote) = MockManage::new();
        let mut forwarder = ReverseForwarder::new(manage);

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

        let (manage, _remote) = MockManage::new();
        let mut forwarder = ReverseForwarder::new(manage);

        let _port = forwarder.start_tcp("127.0.0.1", 0).await.unwrap();
        forwarder.start_unix(sock_str).await.unwrap();

        drop(forwarder);

        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
