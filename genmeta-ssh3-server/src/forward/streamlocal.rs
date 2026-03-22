//! Unix domain socket forwarding (`direct-streamlocal@openssh.com` /
//! `forwarded-streamlocal@openssh.com`).
//!
//! Implements the streamlocal (Unix socket) forwarding channels defined in
//! OpenSSH's streamlocal extension.
//!
//! ## Direct streamlocal (`direct-streamlocal@openssh.com`)
//!
//! Client-initiated Unix socket forwarding. After the [`ChannelHeader`] is read,
//! the stream carries:
//!
//! 1. `socket_path` — [`SshString`]
//! 2. `reserved` — [`SshString`] (empty, reserved for future use)
//! 3. `reserved` — [`VarInt`] (uint32, reserved for future use)
//!
//! The server connects to the Unix socket at `socket_path`, sends
//! `ChannelOpenConfirmation(91)`, and bridges raw bytes between the QUIC
//! stream and the Unix socket. On failure, sends `ChannelOpenFailure(92)`
//! with reason_code=2 (`SSH_OPEN_CONNECT_FAILED`).
//!
//! ## Reverse streamlocal (`streamlocal-forward@openssh.com`)
//!
//! When a client sends a `streamlocal-forward@openssh.com` global request,
//! the server starts a [`UnixListener`] on the specified socket path. For each
//! incoming connection, the server opens a new channel with type
//! `"forwarded-streamlocal@openssh.com"` and bridges raw bytes.
//!
//! **CRITICAL**: After the confirmation, the QUIC stream carries raw bytes —
//! NOT wrapped in `SSH_MSG_CHANNEL_DATA(94)`.

use std::collections::HashMap;
use std::sync::Arc;

use genmeta_ssh::{
    ChannelHeader, ChannelMessage, ChannelOpenFailure, ChannelReader, ChannelWriter,
    DEFAULT_MAX_MESSAGE_SIZE, SshMessage, codec::SshString,
    finish_forwarded_streamlocal_channel, forwarded_streamlocal_header, relay,
};
use genmeta_ssh::{Ssh3Transport, Ssh3TransportClient};
use h3x::codec::{DecodeExt, EncodeExt};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use snafu::Report;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::Instrument;

struct ReverseStreamlocalListenerEntry {
    owner: StreamId,
    created_socket: bool,
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

async fn abort_listener_entry(socket_path: &str, entry: ReverseStreamlocalListenerEntry) {
    entry.handle.abort();
    let _ = entry.handle.await;
    abort_tracked_connections(&entry.connection_tasks).await;
    if entry.created_socket {
        let _ = std::fs::remove_file(socket_path);
    }
}

/// SSH_OPEN_CONNECT_FAILED reason code (RFC 4254 §5.1).
const SSH_OPEN_CONNECT_FAILED: u64 = 2;

// ---------------------------------------------------------------------------
// Direct streamlocal channel
// ---------------------------------------------------------------------------

/// Handle a `direct-streamlocal@openssh.com` channel.
///
/// Reads the forwarding request fields from `reader`, attempts to connect
/// to the Unix socket at `socket_path`, and bridges raw bytes between the
/// QUIC stream and the Unix socket.
pub async fn handle_direct_streamlocal<R, W>(
    _header: ChannelHeader,
    mut reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Parse request_data fields.
    let socket_path: SshString = reader.decode_one().await.map_err(io::Error::other)?;
    let _reserved_string: SshString = reader.decode_one().await.map_err(io::Error::other)?;
    let _reserved_uint32: VarInt = reader.decode_one().await?;

    // Attempt Unix socket connection.
    let unix_stream = match UnixStream::connect(&*socket_path).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(
                path = &*socket_path,
                error = %Report::from_error(&e),
                "direct-streamlocal connect failed"
            );
            let failure = SshMessage::Channel(ChannelMessage::OpenFailure(ChannelOpenFailure {
                reason_code: VarInt::from(SSH_OPEN_CONNECT_FAILED as u8),
                description: "connect failed".into(),
            }));
            writer.encode_one(failure).await.map_err(io::Error::other)?;
            return Ok(());
        }
    };

    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::Channel(ChannelMessage::OpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    });
    writer.encode_one(confirm).await.map_err(io::Error::other)?;

    // Bridge raw bytes bidirectionally between QUIC stream and Unix socket.
    let (unix_reader, unix_writer) = unix_stream.into_split();

    let q2u = tokio::spawn(relay(reader, unix_writer));
    let u2q = tokio::spawn(relay(unix_reader, writer));

    // Wait for both directions, handle errors.
    let (r1, r2) = tokio::join!(q2u, u2q);
    if let Ok(Err(e)) = r1 {
        tracing::warn!(error = %Report::from_error(&e), "relay quic→unix error");
    }
    if let Ok(Err(e)) = r2 {
        tracing::warn!(error = %Report::from_error(&e), "relay unix→quic error");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Request / response data structures
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// forwarded-streamlocal@openssh.com channel request_data encoding
// ---------------------------------------------------------------------------

// Encode forwarded-streamlocal@openssh.com channel request_data fields onto a stream.
//
// Fields:
// - socket_path: SshString
// - reserved: SshString (empty)

// ---------------------------------------------------------------------------
// ReverseStreamlocalForwarder
// ---------------------------------------------------------------------------

/// Manages active reverse streamlocal forwarding listeners.
///
/// When a client sends a `streamlocal-forward@openssh.com` global request,
/// the server calls [`start_listening`] which binds a `UnixListener` and
/// spawns an accept loop. When `cancel-streamlocal-forward@openssh.com`
/// arrives, [`stop_listening`] aborts the task and removes the socket file.
pub struct ReverseStreamlocalForwarder {
    /// Active listeners keyed by socket_path.
    /// The JoinHandle can be aborted to stop the listener.
    listeners: Arc<Mutex<HashMap<String, ReverseStreamlocalListenerEntry>>>,
}

impl ReverseStreamlocalForwarder {
    /// Create a new `ReverseStreamlocalForwarder` with no active listeners.
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start listening on a Unix socket at `socket_path`.
    ///
    /// The accept loop is spawned as a background task. Each accepted
    /// connection will be handled but requires a channel open mechanism
    /// (via the conversation layer) which will be integrated later.
    pub async fn start_listening(
        &self,
        socket_path: &str,
        transport: Ssh3TransportClient,
        conversation_id: StreamId,
    ) -> io::Result<()> {
        let listener = UnixListener::bind(socket_path)?;

        let key = socket_path.to_string();

        // Clone socket_path for use inside the spawned task.
        let socket_path_clone = socket_path.to_string();

        let connection_tasks = Arc::new(Mutex::new(TrackedConnectionTasks::default()));
        let accept_loop_tasks = Arc::clone(&connection_tasks);

        // Spawn the accept loop as a background task.
        let handle = tokio::spawn(
            async move {
                loop {
                    match listener.accept().await {
                        Ok((unix_stream, _peer_addr)) => {
                            let transport = transport.clone();
                            let path = socket_path_clone.clone();
                            let conv_id = conversation_id;
                            let connection_handle = tokio::spawn(async move {
                            let header = forwarded_streamlocal_header(conv_id, &path);
                            match transport.open_channel(Some(header)).await {
                                Ok((from_remote_rx, to_remote_tx)) => {
                                    let reader = ChannelReader::new(from_remote_rx);
                                    let writer = ChannelWriter::new(to_remote_tx);
                                    if let Err(e) = finish_forwarded_streamlocal_channel(
                                        reader, writer, unix_stream,
                                    ).await {
                                        tracing::warn!(
                                            error = %Report::from_error(&e),
                                            "forwarded-streamlocal channel error"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %Report::from_error(&e),
                                        "failed to open transport channel for forwarded-streamlocal"
                                    );
                                }
                            }
                        }.in_current_span());
                            register_tracked_connection(&accept_loop_tasks, connection_handle)
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %Report::from_error(&e),
                                "reverse-streamlocal accept error"
                            );
                            break;
                        }
                    }
                }
            }
            .in_current_span(),
        );

        let old_entry = {
            let mut listeners = self.listeners.lock().await;
            listeners.insert(
                key,
                ReverseStreamlocalListenerEntry {
                    owner: conversation_id,
                    created_socket: true,
                    handle,
                    connection_tasks,
                },
            )
        };
        if let Some(old_entry) = old_entry {
            abort_listener_entry(socket_path, old_entry).await;
        }

        Ok(())
    }

    /// Stop listening on the Unix socket at `socket_path`.
    ///
    /// Returns `true` if a listener was found and stopped, `false` otherwise.
    /// Also removes the socket file from the filesystem.
    pub async fn stop_listening(&self, socket_path: &str, owner: StreamId) -> bool {
        let key = socket_path.to_string();
        let entry = {
            let mut listeners = self.listeners.lock().await;
            match listeners.get(&key) {
                Some(entry) if entry.owner == owner => {}
                Some(_) => return false,
                None => return false,
            }

            listeners
                .remove(&key)
                .expect("listener should exist after ownership check")
        };
        abort_listener_entry(socket_path, entry).await;
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
                    entries.push((key, entry));
                }
            }
            entries
        };

        for (key, entry) in entries {
            abort_listener_entry(&key, entry).await;
        }
    }
}
impl Default for ReverseStreamlocalForwarder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// handle_forwarded_streamlocal_channel
// ---------------------------------------------------------------------------

/// Handle a server-initiated `forwarded-streamlocal@openssh.com` channel.
///
/// This function is called when a new connection arrives on a reverse-
/// forwarded Unix socket. It:
///
/// 1. Writes a [`ChannelHeader`] with channel_type `"forwarded-streamlocal@openssh.com"`
/// 2. Writes the request_data fields (socket_path, reserved)
/// 3. Reads a response from `reader` — either `ChannelOpenConfirmation(91)` or
///    `ChannelOpenFailure(92)`
/// 4. On confirmation, bridges raw bytes between the Unix stream and the QUIC stream
/// 5. On failure, closes the Unix stream gracefully
///
/// **CRITICAL**: Raw bytes are bridged — NO `SSH_MSG_CHANNEL_DATA(94)` wrapping.
pub async fn handle_forwarded_streamlocal_channel<R, W>(
    reader: R,
    mut writer: W,
    unix_stream: UnixStream,
    socket_path: &str,
    conversation_id: StreamId,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let header = forwarded_streamlocal_header(conversation_id, socket_path);
    writer.encode_one(header).await.map_err(io::Error::other)?;
    finish_forwarded_streamlocal_channel(reader, writer, unix_stream)
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
        ChannelMessage, ChannelOpenBody, ChannelOpenFailure,
        DEFAULT_MAX_MESSAGE_SIZE, ChannelHeader, SshMessage, codec::SshString,
    };
    use genmeta_ssh::{CancelStreamlocalForwardRequest, StreamlocalForwardRequest};
    use genmeta_ssh::{
        Ssh3Transport, Ssh3TransportClient, Ssh3TransportServerShared, TransportError,
    };
    use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
    use h3x::stream_id::StreamId;
    use h3x::varint::VarInt;
    use remoc::rtc::ServerShared;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::sync::Notify;

    struct TestTransport;

    impl Ssh3Transport for TestTransport {
        async fn accept_channel(
            &self,
        ) -> Result<
            Option<(
                ChannelHeader,
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            )>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            ),
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

    struct BlockingTransport {
        started: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
        release: Arc<Notify>,
    }

    impl Ssh3Transport for BlockingTransport {
        async fn accept_channel(
            &self,
        ) -> Result<
            Option<(
                ChannelHeader,
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            )>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            ),
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
    /// Atomic counter for unique test socket paths.
    static SOCK_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Generate a unique test socket path.
    fn test_sock_path(label: &str) -> String {
        let id = SOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("/tmp/test-ssh3-streamlocal-{label}-{pid}-{id}.sock")
    }

    /// Encode direct-streamlocal request_data fields into bytes.
    async fn encode_request_data(
        socket_path: &str,
        reserved_string: &str,
        reserved_uint32: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::from(socket_path.to_owned())
            .encode_into(&mut buf)
            .await
            .unwrap();
        SshString::from(reserved_string.to_owned())
            .encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(reserved_uint32)).await.unwrap();
        buf
    }

    // -------------------------------------------------------------------
    // Test 1: direct streamlocal request_data roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_streamlocal_request_data_roundtrip() {
        let data = encode_request_data("/var/run/app.sock", "", 0).await;

        let mut reader = &data[..];
        let socket_path = SshString::decode_from(&mut reader).await.unwrap();
        let reserved_string = SshString::decode_from(&mut reader).await.unwrap();
        let reserved_uint32: VarInt = reader.decode_one().await.unwrap();

        assert_eq!(socket_path, SshString::from("/var/run/app.sock"));
        assert_eq!(reserved_string, SshString::from(""));
        assert_eq!(reserved_uint32.into_inner(), 0);
    }

    // -------------------------------------------------------------------
    // Test 2: direct streamlocal request_data hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_streamlocal_request_data_hex_dump() {
        let data = encode_request_data("/x", "", 0).await;

        // socket_path "/x": varint(2)=0x02, b"/x"=[0x2f, 0x78]
        // reserved_string "": varint(0)=0x00
        // reserved_uint32 0: varint(0)=0x00
        assert_eq!(
            data,
            vec![
                0x02, 0x2f, 0x78, // "/x"
                0x00, // ""
                0x00, // 0
            ]
        );
    }

    // -------------------------------------------------------------------
    // Test 3: direct streamlocal full lifecycle (Unix socket echo server)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_streamlocal_roundtrip() {
        let sock_path = test_sock_path("roundtrip");

        // Start a Unix socket echo server.
        let listener = UnixListener::bind(&sock_path).unwrap();
        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        // Build the request_data fields.
        let request_data = encode_request_data(&sock_path, "", 0).await;

        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(1u8)),
            max_message_size: VarInt::from(1u32 << 20),
            body: ChannelOpenBody::Session,
        };

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Write request_data fields, then "hello", then close write side.
        let client_send = tokio::spawn(async move {
            client_writer.write_all(&request_data).await.unwrap();
            client_writer.write_all(b"hello").await.unwrap();
            drop(client_writer);
        });

        // Server handles the channel.
        let server_handle = tokio::spawn(async move {
            handle_direct_streamlocal(header, server_reader, server_writer)
                .await
                .unwrap();
        });

        // Read ChannelOpenConfirmation from the server.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match confirm {
            SshMessage::Channel(ChannelMessage::OpenConfirmation { max_message_size }) => {
                assert_eq!(max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
            }
            other => panic!("expected ChannelOpenConfirmation, got {other:?}"),
        }

        // Read the echoed data (raw bytes, NOT wrapped in ChannelData).
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello", "echoed data should be raw bytes 'hello'");

        client_send.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();

        // Clean up socket file.
        let _ = std::fs::remove_file(&sock_path);
    }

    // -------------------------------------------------------------------
    // Test 4: direct streamlocal missing socket → ChannelOpenFailure
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn streamlocal_connect_failure() {
        let sock_path = test_sock_path("missing");
        // Don't create any socket — connection should fail.

        let request_data = encode_request_data(&sock_path, "", 0).await;

        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(1u8)),
            max_message_size: VarInt::from(1u32 << 20),
            body: ChannelOpenBody::Session,
        };

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Write request_data then close.
        client_writer.write_all(&request_data).await.unwrap();
        drop(client_writer);

        // Server handles the channel.
        handle_direct_streamlocal(header, server_reader, server_writer)
            .await
            .unwrap();

        // Should receive ChannelOpenFailure(92) with reason_code=2.
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match msg {
            SshMessage::Channel(ChannelMessage::OpenFailure(ChannelOpenFailure {
                reason_code,
                description,
            })) => {
                assert_eq!(
                    reason_code,
                    VarInt::from(SSH_OPEN_CONNECT_FAILED as u8),
                    "reason_code should be 2 (SSH_OPEN_CONNECT_FAILED)"
                );
                assert!(
                    description.contains("connect failed"),
                    "description should mention connect failure, got: {description}"
                );
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 5: streamlocal forward request roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn streamlocal_forward_request_roundtrip() {
        let req = StreamlocalForwardRequest {
            socket_path: "/var/run/my.sock".into(),
        };
        let mut bytes = Vec::new();
        bytes.encode_one(req.clone()).await.unwrap();
        let decoded: StreamlocalForwardRequest = bytes.as_slice().decode_one().await.unwrap();
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------
    // Test 6: cancel streamlocal forward request roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cancel_streamlocal_forward_request_roundtrip() {
        let req = CancelStreamlocalForwardRequest {
            socket_path: "/tmp/agent.sock".into(),
        };
        let mut bytes = Vec::new();
        bytes.encode_one(req.clone()).await.unwrap();
        let decoded: CancelStreamlocalForwardRequest = bytes.as_slice().decode_one().await.unwrap();
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------
    // Test 7: forwarder start/stop
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn forwarder_start_stop() {
        let forwarder = ReverseStreamlocalForwarder::new();
        let sock_path = test_sock_path("fwd-startstop");

        // Start listening.
        forwarder
            .start_listening(
                &sock_path,
                test_transport_client(),
                h3x::stream_id::StreamId(VarInt::from(1u8)),
            )
            .await
            .unwrap();

        // Verify the listener is active by checking internal state.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(listeners.contains_key(&sock_path));
        }

        // Stop listening.
        let owner = h3x::stream_id::StreamId(VarInt::from(1u8));
        let stopped = forwarder.stop_listening(&sock_path, owner).await;
        assert!(stopped, "should return true when listener exists");

        // Verify it's gone.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(!listeners.contains_key(&sock_path));
        }

        // Stopping again should return false.
        let stopped_again = forwarder.stop_listening(&sock_path, owner).await;
        assert!(
            !stopped_again,
            "should return false when listener doesn't exist"
        );

        // Socket file should have been cleaned up by stop_listening.
        assert!(
            !std::path::Path::new(&sock_path).exists(),
            "socket file should be removed after stop"
        );
    }

    #[tokio::test]
    async fn non_owner_cannot_remove_streamlocal_listener() {
        let forwarder = ReverseStreamlocalForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(7u8));
        let other_owner = h3x::stream_id::StreamId(VarInt::from(8u8));
        let sock_path = test_sock_path("non-owner");

        forwarder
            .start_listening(&sock_path, test_transport_client(), owner)
            .await
            .unwrap();

        let stopped = forwarder.stop_listening(&sock_path, other_owner).await;
        assert!(!stopped, "non-owner should not stop streamlocal listener");
        assert!(
            std::path::Path::new(&sock_path).exists(),
            "socket path should remain for owner listener"
        );

        forwarder.cleanup_for_owner(owner).await;
    }

    #[tokio::test]
    async fn cleanup_for_owner_is_idempotent_and_preserves_non_owned_socket() {
        let forwarder = ReverseStreamlocalForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(9u8));
        let sock_path = test_sock_path("cleanup");
        let foreign_sock_path = test_sock_path("foreign");

        let foreign_listener = UnixListener::bind(&foreign_sock_path).unwrap();

        forwarder
            .start_listening(&sock_path, test_transport_client(), owner)
            .await
            .unwrap();

        forwarder.cleanup_for_owner(owner).await;
        forwarder.cleanup_for_owner(owner).await;

        {
            let listeners = forwarder.listeners.lock().await;
            assert!(!listeners.contains_key(&sock_path));
        }

        assert!(
            !std::path::Path::new(&sock_path).exists(),
            "owned socket should be removed after cleanup"
        );
        assert!(
            std::path::Path::new(&foreign_sock_path).exists(),
            "non-owned pre-existing socket should be preserved"
        );

        drop(foreign_listener);
        let _ = std::fs::remove_file(&foreign_sock_path);
    }

    #[tokio::test]
    async fn cleanup_for_owner_preserves_other_owner_listener_and_socket() {
        let forwarder = ReverseStreamlocalForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(10u8));
        let other_owner = h3x::stream_id::StreamId(VarInt::from(11u8));
        let owned_sock_path = test_sock_path("owned-cleanup");
        let other_sock_path = test_sock_path("other-cleanup");

        forwarder
            .start_listening(&owned_sock_path, test_transport_client(), owner)
            .await
            .unwrap();
        forwarder
            .start_listening(&other_sock_path, test_transport_client(), other_owner)
            .await
            .unwrap();

        forwarder.cleanup_for_owner(owner).await;
        forwarder.cleanup_for_owner(owner).await;

        {
            let listeners = forwarder.listeners.lock().await;
            assert!(
                !listeners.contains_key(&owned_sock_path),
                "owned listener should be removed"
            );
            assert!(
                listeners.contains_key(&other_sock_path),
                "other owner's listener must remain registered"
            );
        }

        assert!(
            !std::path::Path::new(&owned_sock_path).exists(),
            "owned socket should be removed after cleanup"
        );
        assert!(
            std::path::Path::new(&other_sock_path).exists(),
            "other owner's socket should remain after cleanup"
        );

        let other_connect = UnixStream::connect(&other_sock_path).await;
        assert!(
            other_connect.is_ok(),
            "other owner's streamlocal listener should remain reachable"
        );

        forwarder.cleanup_for_owner(other_owner).await;
        let _ = std::fs::remove_file(&owned_sock_path);
        let _ = std::fs::remove_file(&other_sock_path);
    }

    #[tokio::test]
    async fn cleanup_after_stop_listening_aborts_tracked_connection_tasks() {
        let forwarder = ReverseStreamlocalForwarder::new();
        let owner = h3x::stream_id::StreamId(VarInt::from(12u8));
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        let sock_path = test_sock_path("partial-cleanup");

        forwarder
            .start_listening(
                &sock_path,
                blocking_transport_client(started.clone(), dropped.clone(), release.clone()),
                owner,
            )
            .await
            .unwrap();

        let unix_stream = UnixStream::connect(&sock_path)
            .await
            .expect("connection should reach listener before cleanup");

        wait_for_counter(&started, 1).await;

        assert!(forwarder.stop_listening(&sock_path, owner).await);
        forwarder.cleanup_for_owner(owner).await;
        forwarder.cleanup_for_owner(owner).await;

        wait_for_counter(&dropped, 1).await;

        assert!(
            !std::path::Path::new(&sock_path).exists(),
            "socket should be removed after stop + cleanup"
        );

        drop(unix_stream);
        release.notify_waiters();
    }

    // -------------------------------------------------------------------
    // Test 8: forwarded streamlocal channel lifecycle (with echo server)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn forwarded_streamlocal_channel_lifecycle() {
        let sock_path = test_sock_path("fwd-lifecycle");

        // Start a Unix socket echo server.
        let listener = UnixListener::bind(&sock_path).unwrap();
        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        // Connect a Unix client to the echo server (simulating an incoming
        // connection on a reverse-forwarded socket).
        let unix_stream = UnixStream::connect(&sock_path).await.unwrap();

        // Mock QUIC streams.
        let (client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Server opens the forwarded-streamlocal channel.
        let fwd_sock_path = sock_path.clone();
        let server_handle = tokio::spawn(async move {
            handle_forwarded_streamlocal_channel(
                server_reader,
                server_writer,
                unix_stream,
                &fwd_sock_path,
                h3x::stream_id::StreamId(VarInt::from(42u8)),
            )
            .await
            .unwrap();
        });

        // Client side: read ChannelHeader (includes request_data in body).
        let header = ChannelHeader::decode_from(&mut client_reader)
            .await
            .unwrap();
        assert_eq!(header.session_id, StreamId(VarInt::from(42u8)));
        assert_eq!(header.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
        match &header.body {
            ChannelOpenBody::ForwardedStreamlocal(req) => {
                assert_eq!(req.socket_path, SshString::from(sock_path.clone()));
            }
            other => panic!("expected ForwardedStreamlocal body, got {other:?}"),
        }

        // Client side: send ChannelOpenConfirmation, then data, then close.
        let client_handle = tokio::spawn(async move {
            let mut client_writer = client_writer;
            let confirm = SshMessage::Channel(ChannelMessage::OpenConfirmation {
                max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            });
            confirm.encode_into(&mut client_writer).await.unwrap();

            // Send data through the channel (raw bytes, no wrapping).
            client_writer.write_all(b"hello-streamlocal").await.unwrap();
            drop(client_writer);
        });

        // Read the echoed data from the server side (comes via Unix echo → QUIC).
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(
            echoed, b"hello-streamlocal",
            "echoed data should be raw bytes"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();

        // Clean up socket file.
        let _ = std::fs::remove_file(&sock_path);
    }
}
