//! Reverse TCP forwarding (`tcpip-forward` / `cancel-tcpip-forward`).
//!
//! Implements the server-side handling of RFC 4254 §7.1 — when a client sends
//! a `tcpip-forward` global request, the server starts a [`TcpListener`] on
//! the specified address/port. For each incoming TCP connection, the server
//! opens a new channel with type `"forwarded-tcpip"` and bridges raw bytes
//! between the TCP socket and the QUIC stream.
//!
//! **CRITICAL**: After the channel open confirmation, the QUIC stream carries
//! raw bytes — NOT wrapped in `SSH_MSG_CHANNEL_DATA(94)`.

use std::collections::HashMap;
use std::sync::Arc;

use genmeta_ssh::{ChannelReader, ChannelWriter, finish_forwarded_tcpip_channel, forwarded_tcpip_header};
use genmeta_ssh::{Ssh3Transport, Ssh3TransportClient};
use h3x::codec::EncodeExt;
use h3x::stream_id::StreamId;
use snafu::Report;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::Instrument;

struct ReverseTcpListenerEntry {
    owner: StreamId,
    handle: tokio::task::JoinHandle<()>,
    connection_tasks: Arc<Mutex<TrackedConnectionTasks>>,
}

#[derive(Default)]
struct TrackedConnectionTasks {
    shutting_down: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

async fn register_tracked_connection(
    tracked_tasks: &Arc<Mutex<TrackedConnectionTasks>>,
    handle: tokio::task::JoinHandle<()>,
) {
    let mut tracked_tasks = tracked_tasks.lock().await;
    if tracked_tasks.shutting_down {
        handle.abort();
    } else {
        tracked_tasks.handles.push(handle);
    }
}

async fn abort_tracked_connections(tracked_tasks: &Arc<Mutex<TrackedConnectionTasks>>) {
    let handles = {
        let mut tracked_tasks = tracked_tasks.lock().await;
        tracked_tasks.shutting_down = true;
        std::mem::take(&mut tracked_tasks.handles)
    };

    for handle in handles {
        handle.abort();
        let _ = handle.await;
    }
}

async fn abort_listener_entry(entry: ReverseTcpListenerEntry) {
    entry.handle.abort();
    let _ = entry.handle.await;
    abort_tracked_connections(&entry.connection_tasks).await;
}

// ---------------------------------------------------------------------------
// Request / response data structures
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// forwarded-tcpip channel request_data encoding/decoding
// ---------------------------------------------------------------------------

// Encode forwarded-tcpip channel request_data fields onto a stream.
//
// Fields (RFC 4254 §7.2):
// - connected_address: SshString
// - connected_port: VarInt
// - originator_address: SshString
// - originator_port: VarInt

// ---------------------------------------------------------------------------
// ReverseTcpForwarder
// ---------------------------------------------------------------------------

/// Manages active reverse TCP forwarding listeners.
///
/// When a client sends a `tcpip-forward` global request, the server calls
/// [`start_listening`] which binds a `TcpListener` and spawns an accept loop.
/// When `cancel-tcpip-forward` arrives, [`stop_listening`] aborts the task.
#[allow(clippy::type_complexity)]
pub struct ReverseTcpForwarder {
    /// Active listeners keyed by (bind_address, bind_port).
    /// The JoinHandle can be aborted to stop the listener.
    listeners: Arc<Mutex<HashMap<(String, u16), ReverseTcpListenerEntry>>>,
}

impl ReverseTcpForwarder {
    /// Create a new `ReverseTcpForwarder` with no active listeners.
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start listening on `bind_address:bind_port`.
    ///
    /// If `bind_port == 0`, an ephemeral port is allocated by the OS.
    /// Returns the actual port being listened on.
    ///
    /// The accept loop is spawned as a background task. Each accepted TCP
    /// connection will be handled but requires a channel open mechanism
    /// (via the conversation layer) which will be integrated later.
    pub async fn start_listening(
        &self,
        bind_address: &str,
        bind_port: u16,
        transport: Ssh3TransportClient,
        conversation_id: StreamId,
    ) -> io::Result<u16> {
        let addr = format!("{}:{}", bind_address, bind_port);
        let listener = TcpListener::bind(&addr).await?;
        let actual_port = listener.local_addr()?.port();

        let key = (bind_address.to_string(), actual_port);

        // Clone bind_address for use inside the spawned task.
        let bind_address_clone = bind_address.to_string();

        let connection_tasks = Arc::new(Mutex::new(TrackedConnectionTasks::default()));
        let accept_loop_tasks = Arc::clone(&connection_tasks);

        // Spawn the accept loop as a background task.
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp_stream, peer_addr)) => {
                        let transport = transport.clone();
                        let addr = bind_address_clone.clone();
                        let port = actual_port;
                        let conv_id = conversation_id;
                        let connection_handle = tokio::spawn(async move {
                            let header = forwarded_tcpip_header(
                                conv_id,
                                &addr,
                                port,
                                &peer_addr.ip().to_string(),
                                peer_addr.port(),
                            );
                            match transport.open_channel(Some(header)).await {
                                Ok((from_remote_rx, to_remote_tx)) => {
                                    let reader = ChannelReader::new(from_remote_rx);
                                    let writer = ChannelWriter::new(to_remote_tx);
                                    if let Err(e) = finish_forwarded_tcpip_channel(
                                        reader, writer, tcp_stream,
                                    ).await {
                                        tracing::warn!(
                                            error = %Report::from_error(&e),
                                            "forwarded-tcpip channel error"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %Report::from_error(&e),
                                        "failed to open transport channel for forwarded-tcpip"
                                    );
                                }
                            }
                        }.in_current_span());
                        register_tracked_connection(&accept_loop_tasks, connection_handle).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %Report::from_error(&e), "reverse-tcp accept error");
                        break;
                    }
                }
            }
        }.in_current_span());

        let old_entry = {
            let mut listeners = self.listeners.lock().await;
            listeners.insert(
                key,
                ReverseTcpListenerEntry {
                    owner: conversation_id,
                    handle,
                    connection_tasks,
                },
            )
        };
        if let Some(old_entry) = old_entry {
            abort_listener_entry(old_entry).await;
        }

        Ok(actual_port)
    }

    /// Stop listening on `bind_address:bind_port`.
    ///
    /// Returns `true` if a listener was found and stopped, `false` otherwise.
    pub async fn stop_listening(&self, bind_address: &str, bind_port: u16, owner: StreamId) -> bool {
        let key = (bind_address.to_string(), bind_port);
        let entry = {
            let mut listeners = self.listeners.lock().await;
            match listeners.get(&key) {
                Some(entry) if entry.owner == owner => {}
                Some(_) => return false,
                None => return false,
            }

            listeners.remove(&key).expect("listener should exist after ownership check")
        };
        abort_listener_entry(entry).await;
        true
    }

    pub async fn cleanup_for_owner(&self, owner: StreamId) {
        let entries = {
            let mut listeners = self.listeners.lock().await;
            let keys_to_remove: Vec<_> = listeners
                .iter()
                .filter_map(|(key, entry)| (entry.owner == owner).then_some(key.clone()))
                .collect();

            let mut entries = Vec::with_capacity(keys_to_remove.len());
            for key in keys_to_remove {
                if let Some(entry) = listeners.remove(&key) {
                    entries.push(entry);
                }
            }
            entries
        };

        for entry in entries {
            abort_listener_entry(entry).await;
        }
    }
}
impl Default for ReverseTcpForwarder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// handle_forwarded_tcpip_channel
// ---------------------------------------------------------------------------

/// Handle a server-initiated `forwarded-tcpip` channel.
///
/// This function is called when a new TCP connection arrives on a reverse-
/// forwarded port. It:
///
/// 1. Writes a [`ChannelHeader`] with channel_type `"forwarded-tcpip"` to `writer`
/// 2. Writes the request_data fields (connected_addr/port, originator_addr/port)
/// 3. Reads a response from `reader` — either `ChannelOpenConfirmation(91)` or
#[allow(clippy::too_many_arguments)]
///    `ChannelOpenFailure(92)`
/// 4. On confirmation, bridges raw bytes between the TCP stream and the QUIC stream
/// 5. On failure, closes the TCP stream gracefully
///
/// **CRITICAL**: Raw bytes are bridged — NO `SSH_MSG_CHANNEL_DATA(94)` wrapping.
pub async fn handle_forwarded_tcpip_channel<R, W>(
    reader: R,
    mut writer: W,
    tcp_stream: tokio::net::TcpStream,
    connected_addr: &str,
    connected_port: u16,
    originator_addr: &str,
    originator_port: u16,
    conversation_id: StreamId,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let header = forwarded_tcpip_header(
        conversation_id,
        connected_addr,
        connected_port,
        originator_addr,
        originator_port,
    );
    writer.encode_one(header).await.map_err(io::Error::other)?;
    finish_forwarded_tcpip_channel(reader, writer, tcp_stream)
        .await
        .map_err(io::Error::other)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh::{
        ChannelMessage,
        ChannelOpenBody,
        ChannelOpenFailure,
        DEFAULT_MAX_MESSAGE_SIZE,
        ChannelHeader,
        SshMessage,
        codec::SshString,
    };
    use genmeta_ssh::{CancelTcpipForwardRequest, TcpipForwardReply, TcpipForwardRequest};
    use genmeta_ssh::{Ssh3Transport, Ssh3TransportServerShared, TransportError};
    use h3x::codec::{DecodeExt, DecodeFrom, EncodeInto};
    use h3x::stream_id::StreamId;
    use h3x::varint::VarInt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use remoc::rtc::ServerShared;
    use tokio::sync::Notify;

    struct TestTransport;

    impl Ssh3Transport for TestTransport {
        async fn accept_channel(&self) -> Result<
            Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
            TransportError,
        > {
            let (tx, rx) = remoc::rch::mpsc::channel(16);
            Ok((rx, tx))
        }
    }

    fn test_transport_client() -> Ssh3TransportClient {
        let (server, client) = Ssh3TransportServerShared::new(Arc::new(TestTransport), 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    async fn wait_for_counter(counter: &AtomicUsize, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while counter.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out waiting for expected counter value");
    }

    async fn assert_tcp_port_eventually_closes(port: u16, context: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{context}"));
    }

    struct BlockingTransport {
        started: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        release: Arc<Notify>,
    }

    impl Ssh3Transport for BlockingTransport {
        async fn accept_channel(&self) -> Result<
            Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
            TransportError,
        > {
            struct DropGuard(Arc<AtomicUsize>);

            impl Drop for DropGuard {
                fn drop(&mut self) {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }

            self.started.fetch_add(1, Ordering::SeqCst);
            let _guard = DropGuard(Arc::clone(&self.dropped));
            self.release.notified().await;
            Err(TransportError::Other("released".into()))
        }
    }

    fn blocking_transport_client(
        started: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        release: Arc<Notify>,
    ) -> Ssh3TransportClient {
        let transport = Arc::new(BlockingTransport {
            started,
            dropped,
            release,
        });
        let (server, client) = Ssh3TransportServerShared::new(transport, 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    // -------------------------------------------------------------------
    // Test 1: tcpip_forward_request_roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_request_roundtrip() {
        let req = TcpipForwardRequest {
            bind_address: "0.0.0.0".into(),
            bind_port: VarInt::from(8080u32),
        };
        let mut bytes = Vec::new();
        bytes.encode_one(req.clone()).await.unwrap();
        let decoded: TcpipForwardRequest = bytes.as_slice().decode_one().await.unwrap();
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------
    // Test 2: tcpip_forward_request_hex_dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_request_hex_dump() {
        let req = TcpipForwardRequest {
            bind_address: "hi".into(),
            bind_port: VarInt::from(22u8),
        };
        let mut bytes = Vec::new();
        bytes.encode_one(req).await.unwrap();
        // "hi": varint(2)=0x02, b"hi"=[0x68, 0x69]
        // port 22: varint(22) = 1-byte [0x16]
        assert_eq!(
            bytes,
            vec![0x02, 0x68, 0x69, 0x16],
        );
    }

    // -------------------------------------------------------------------
    // Test 3: cancel_tcpip_forward_request_roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cancel_tcpip_forward_request_roundtrip() {
        let req = CancelTcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: VarInt::from(3000u32),
        };
        let mut bytes = Vec::new();
        bytes.encode_one(req.clone()).await.unwrap();
        let decoded: CancelTcpipForwardRequest = bytes.as_slice().decode_one().await.unwrap();
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------
    // Test 4: tcpip_forward_reply_roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_reply_roundtrip() {
        let reply = TcpipForwardReply {
            allocated_port: VarInt::from(49152u32),
        };
        let mut bytes = Vec::new();
        bytes.encode_one(reply.clone()).await.unwrap();
        let decoded: TcpipForwardReply = bytes.as_slice().decode_one().await.unwrap();
        assert_eq!(decoded, reply);
    }

    // -------------------------------------------------------------------
    // Test 5: forwarder_start_stop
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn forwarder_start_stop() {
        let forwarder = ReverseTcpForwarder::new();

        // Start listening on an ephemeral port.
        let port = forwarder
            .start_listening(
                "127.0.0.1",
                0,
                test_transport_client(),
                h3x::stream_id::StreamId(VarInt::from(1u8)),
            )
            .await
            .unwrap();
        assert!(port > 0, "allocated port should be > 0");

        // Verify the listener is active by checking internal state.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(listeners.contains_key(&("127.0.0.1".to_string(), port)));
        }

        // Stop listening.
        let owner = h3x::stream_id::StreamId(VarInt::from(1u8));
        let stopped = forwarder.stop_listening("127.0.0.1", port, owner).await;
        assert!(stopped, "should return true when listener exists");

        // Verify it's gone.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(!listeners.contains_key(&("127.0.0.1".to_string(), port)));
        }

        // Stopping again should return false.
        let stopped_again = forwarder.stop_listening("127.0.0.1", port, owner).await;
        assert!(!stopped_again, "should return false when listener doesn't exist");
    }

    // -------------------------------------------------------------------
    // Test 6: forwarder_dynamic_port
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn forwarder_dynamic_port() {
        let forwarder = ReverseTcpForwarder::new();

        // Bind with port 0 twice — should get different ports.
        let port1 = forwarder
            .start_listening(
                "127.0.0.1",
                0,
                test_transport_client(),
                h3x::stream_id::StreamId(VarInt::from(1u8)),
            )
            .await
            .unwrap();
        let port2 = forwarder
            .start_listening(
                "127.0.0.1",
                0,
                test_transport_client(),
                h3x::stream_id::StreamId(VarInt::from(2u8)),
            )
            .await
            .unwrap();

        assert!(port1 > 0);
        assert!(port2 > 0);
        assert_ne!(port1, port2, "two dynamic allocations should yield different ports");

        // Clean up.
        forwarder
            .stop_listening("127.0.0.1", port1, h3x::stream_id::StreamId(VarInt::from(1u8)))
            .await;
        forwarder
            .stop_listening("127.0.0.1", port2, h3x::stream_id::StreamId(VarInt::from(2u8)))
            .await;
    }

    #[tokio::test]
    async fn non_owner_cannot_stop_listener() {
        let forwarder = ReverseTcpForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(7u8));
        let other_owner = h3x::stream_id::StreamId(VarInt::from(8u8));

        let port = forwarder
            .start_listening("127.0.0.1", 0, test_transport_client(), owner)
            .await
            .unwrap();

        let stopped = forwarder.stop_listening("127.0.0.1", port, other_owner).await;
        assert!(!stopped, "non-owner should not stop listener");

        {
            let listeners = forwarder.listeners.lock().await;
            assert!(listeners.contains_key(&("127.0.0.1".to_string(), port)));
        }

        forwarder.cleanup_for_owner(owner).await;
    }

    #[tokio::test]
    async fn cleanup_for_owner_is_idempotent() {
        let forwarder = ReverseTcpForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(9u8));

        let port = forwarder
            .start_listening("127.0.0.1", 0, test_transport_client(), owner)
            .await
            .unwrap();

        forwarder.cleanup_for_owner(owner).await;
        forwarder.cleanup_for_owner(owner).await;

        {
            let listeners = forwarder.listeners.lock().await;
            assert!(!listeners.contains_key(&("127.0.0.1".to_string(), port)));
        }

        assert_tcp_port_eventually_closes(
            port,
            "listener port should be closed within timeout after idempotent cleanup",
        )
        .await;
    }

    #[tokio::test]
    async fn cleanup_for_owner_preserves_other_owner_listener() {
        let forwarder = ReverseTcpForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(10u8));
        let other_owner = h3x::stream_id::StreamId(VarInt::from(11u8));

        let owned_port = forwarder
            .start_listening("127.0.0.1", 0, test_transport_client(), owner)
            .await
            .unwrap();
        let other_port = forwarder
            .start_listening("127.0.0.1", 0, test_transport_client(), other_owner)
            .await
            .unwrap();

        forwarder.cleanup_for_owner(owner).await;
        forwarder.cleanup_for_owner(owner).await;

        {
            let listeners = forwarder.listeners.lock().await;
            assert!(
                !listeners.contains_key(&("127.0.0.1".to_string(), owned_port)),
                "owned listener should be removed"
            );
            assert!(
                listeners.contains_key(&("127.0.0.1".to_string(), other_port)),
                "other owner's listener must remain registered"
            );
        }

        assert_tcp_port_eventually_closes(
            owned_port,
            "owned listener should be closed within timeout after cleanup",
        )
        .await;

        let other_connect = tokio::net::TcpStream::connect(format!("127.0.0.1:{other_port}")).await;
        assert!(other_connect.is_ok(), "other owner's listener should remain reachable");

        forwarder.cleanup_for_owner(other_owner).await;
    }

    #[tokio::test]
    async fn cleanup_after_stop_listening_aborts_tracked_connection_tasks() {
        let forwarder = ReverseTcpForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(12u8));
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());

        let port = forwarder
            .start_listening(
                "127.0.0.1",
                0,
                blocking_transport_client(started.clone(), dropped.clone(), release.clone()),
                owner,
            )
            .await
            .unwrap();

        let tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connection should reach listener before cleanup");

        wait_for_counter(&started, 1).await;

        assert!(forwarder.stop_listening("127.0.0.1", port, owner).await);
        forwarder.cleanup_for_owner(owner).await;
        forwarder.cleanup_for_owner(owner).await;

        wait_for_counter(&dropped, 1).await;

        assert_tcp_port_eventually_closes(
            port,
            "listener should be closed within timeout after stop + cleanup",
        )
        .await;

        drop(tcp_stream);
        release.notify_waiters();
    }

    // -------------------------------------------------------------------
    // Test 7: forwarded_tcpip_channel_lifecycle
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn forwarded_tcpip_channel_lifecycle() {
        // Start a local TCP echo server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        // Connect a TCP client to the echo server (simulating an incoming
        // connection on a reverse-forwarded port).
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Mock QUIC streams.
        // server_writer → client_reader (server writes channel header + request_data)
        // client_writer → server_reader (client writes confirmation + data)
        let (client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Server opens the forwarded-tcpip channel.
        let server_handle = tokio::spawn(async move {
            handle_forwarded_tcpip_channel(
                server_reader,
                server_writer,
                tcp_stream,
                "192.168.1.100",
                80,
                "10.0.0.1",
                54321,
                h3x::stream_id::StreamId(VarInt::from(42u8)),
            )
            .await
            .unwrap();
        });

        // Client side: read ChannelHeader (includes request_data in body).
        let header = ChannelHeader::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(header.session_id, StreamId(VarInt::from(42u8)));
        assert_eq!(header.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        match &header.body {
            ChannelOpenBody::ForwardedTcpip(req) => {
                assert_eq!(req.connected_address, SshString::from("192.168.1.100"));
                assert_eq!(req.connected_port.into_inner(), 80);
                assert_eq!(req.originator_address, SshString::from("10.0.0.1"));
                assert_eq!(req.originator_port.into_inner(), 54321);
            }
            other => panic!("expected ForwardedTcpip body, got {other:?}"),
        }

        // Client side: send ChannelOpenConfirmation, then data, then close.
        let client_handle = tokio::spawn(async move {
            let mut client_writer = client_writer;
            let confirm = SshMessage::Channel(ChannelMessage::OpenConfirmation {
                max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            });
            confirm.encode_into(&mut client_writer).await.unwrap();

            // Send data through the channel (raw bytes, no wrapping).
            client_writer.write_all(b"hello-reverse").await.unwrap();
            drop(client_writer);
        });

        // Read the echoed data from the server side (comes via TCP echo → QUIC).
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello-reverse", "echoed data should be raw bytes");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 8: forwarded_tcpip_channel_rejected
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn forwarded_tcpip_channel_rejected() {
        // Start a local TCP server that we'll connect to.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept one connection then hold it open until we're done.
        let tcp_server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Hold the connection open; it will be dropped when the test ends.
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Mock QUIC streams.
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Server opens the forwarded-tcpip channel.
        let server_handle = tokio::spawn(async move {
            handle_forwarded_tcpip_channel(
                server_reader,
                server_writer,
                tcp_stream,
                "192.168.1.100",
                80,
                "10.0.0.1",
                54321,
                h3x::stream_id::StreamId(VarInt::from(42u8)),
            )
            .await
            .unwrap();
        });

        // Client side: read the header (includes request_data in body).
        let _header = ChannelHeader::decode_from(&mut client_reader).await.unwrap();

        // Client side: send ChannelOpenFailure to reject the channel.
        let failure = SshMessage::Channel(ChannelMessage::OpenFailure(ChannelOpenFailure {
            reason_code: VarInt::from(1u8),
            description: "administratively prohibited".into(),
        }));
        failure.encode_into(&mut client_writer).await.unwrap();
        client_writer.flush().await.unwrap();
        drop(client_writer);

        // Server should return Ok(()) after receiving rejection.
        server_handle.await.unwrap();

        // No data should have been bridged — client_reader should be closed.
        let mut remaining = Vec::new();
        client_reader.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty(), "no data should be bridged after rejection");

        tcp_server.abort();
    }
}
