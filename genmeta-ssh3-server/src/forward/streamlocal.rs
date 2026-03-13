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

use genmeta_ssh3_proto::{codec::ChannelHeader, codec::SshString, message::SshMessage};
use genmeta_ssh3_proto::session::{Ssh3Transport, Ssh3TransportClient};
use h3x::codec::{DecodeExt, DecodeFrom, EncodeInto};
use h3x::varint::VarInt;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::byte_channel::{ChannelReader, ChannelWriter};

/// Default maximum message size advertised in ChannelOpenConfirmation.
const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1 << 20; // 1 MiB

/// Signal value for channel headers (matching conversation.rs CHANNEL_SIGNAL_VALUE).
const CHANNEL_SIGNAL_VALUE: u32 = 0xaf3627e6;

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
    let socket_path = SshString::decode_from(&mut reader).await?;
    let _reserved_string = SshString::decode_from(&mut reader).await?;
    let _reserved_uint32: VarInt = reader.decode_one().await?;

    // Attempt Unix socket connection.
    let unix_stream = match UnixStream::connect(&socket_path.0).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(path = %socket_path.0, %e, "direct-streamlocal connect failed");
            let failure = SshMessage::ChannelOpenFailure {
                reason_code: SSH_OPEN_CONNECT_FAILED,
                description: format!("connect failed: {e}"),
            };
            failure.encode_into(&mut writer).await?;
            return Ok(());
        }
    };

    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    confirm.encode_into(&mut writer).await?;

    // Bridge raw bytes bidirectionally between QUIC stream and Unix socket.
    let (unix_reader, unix_writer) = unix_stream.into_split();

    let q2u = tokio::spawn(super::relay(reader, unix_writer));
    let u2q = tokio::spawn(super::relay(unix_reader, writer));

    // Wait for both directions, handle errors.
    let (r1, r2) = tokio::join!(q2u, u2q);
    if let Ok(Err(e)) = r1 {
        tracing::warn!("relay quic→unix error: {e}");
    }
    if let Ok(Err(e)) = r2 {
        tracing::warn!("relay unix→quic error: {e}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Request / response data structures
// ---------------------------------------------------------------------------

/// Decoded `streamlocal-forward@openssh.com` request data: socket_path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamlocalForwardRequest {
    pub socket_path: String,
}

impl StreamlocalForwardRequest {
    /// Encode into wire format: SshString(socket_path).
    pub async fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString(self.socket_path.clone()).encode_into(&mut buf)
            .await
            .expect("vec write cannot fail");
        buf
    }

    /// Decode from wire format bytes.
    pub async fn decode_from_bytes(data: &[u8]) -> io::Result<Self> {
        let mut reader = data;
        let socket_path = SshString::decode_from(&mut reader).await?;
        Ok(StreamlocalForwardRequest {
            socket_path: socket_path.0,
        })
    }
}

/// Decoded `cancel-streamlocal-forward@openssh.com` request data: socket_path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelStreamlocalForwardRequest {
    pub socket_path: String,
}

impl CancelStreamlocalForwardRequest {
    /// Encode into wire format: SshString(socket_path).
    pub async fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString(self.socket_path.clone()).encode_into(&mut buf)
            .await
            .expect("vec write cannot fail");
        buf
    }

    /// Decode from wire format bytes.
    pub async fn decode_from_bytes(data: &[u8]) -> io::Result<Self> {
        let mut reader = data;
        let socket_path = SshString::decode_from(&mut reader).await?;
        Ok(CancelStreamlocalForwardRequest {
            socket_path: socket_path.0,
        })
    }
}

// ---------------------------------------------------------------------------
// forwarded-streamlocal@openssh.com channel request_data encoding
// ---------------------------------------------------------------------------

/// Encode forwarded-streamlocal@openssh.com channel request_data fields onto a stream.
///
/// Fields:
/// - socket_path: SshString
/// - reserved: SshString (empty)
async fn encode_forwarded_streamlocal_request_data<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    socket_path: &str,
) -> io::Result<()> {
    SshString(socket_path.to_string()).encode_into(&mut *writer).await?;
    // reserved string (empty)
    SshString(String::new()).encode_into(&mut *writer).await?;
    Ok(())
}

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
    listeners: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
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
        conversation_id: u64,
    ) -> io::Result<()> {
        let listener = UnixListener::bind(socket_path)?;

        let key = socket_path.to_string();

        // Clone socket_path for use inside the spawned task.
        let socket_path_clone = socket_path.to_string();

        // Spawn the accept loop as a background task.
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((unix_stream, _peer_addr)) => {
                        let transport = transport.clone();
                        let path = socket_path_clone.clone();
                        let conv_id = conversation_id;
                        tokio::spawn(async move {
                            match transport.open_channel(None).await {
                                Ok((from_remote_rx, to_remote_tx)) => {
                                    let reader = ChannelReader::new(from_remote_rx);
                                    let writer = ChannelWriter::new(to_remote_tx);
                                    if let Err(e) = handle_forwarded_streamlocal_channel(
                                        reader, writer, unix_stream,
                                        &path,
                                        conv_id,
                                    ).await {
                                        tracing::warn!(%e, "forwarded-streamlocal channel error");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(%e, "failed to open transport channel for forwarded-streamlocal");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(%e, "reverse-streamlocal accept error");
                        break;
                    }
                }
            }
        });

        let mut listeners = self.listeners.lock().await;
        // If there was already a listener on this key, abort the old one.
        if let Some(old_handle) = listeners.insert(key, handle) {
            old_handle.abort();
        }

        Ok(())
    }

    /// Stop listening on the Unix socket at `socket_path`.
    ///
    /// Returns `true` if a listener was found and stopped, `false` otherwise.
    /// Also removes the socket file from the filesystem.
    pub async fn stop_listening(&self, socket_path: &str) -> bool {
        let key = socket_path.to_string();
        let mut listeners = self.listeners.lock().await;
        if let Some(handle) = listeners.remove(&key) {
            handle.abort();
            // Clean up the socket file.
            let _ = std::fs::remove_file(socket_path);
            true
        } else {
            false
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
    mut reader: R,
    mut writer: W,
    unix_stream: UnixStream,
    socket_path: &str,
    conversation_id: u64,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // 1. Write ChannelHeader.
    let header = ChannelHeader {
        signal_value: CHANNEL_SIGNAL_VALUE,
        conversation_id,
        channel_type: "forwarded-streamlocal@openssh.com".to_string(),
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    header.encode_into(&mut writer).await?;

    // 2. Write request_data fields.
    encode_forwarded_streamlocal_request_data(&mut writer, socket_path).await?;
    writer.flush().await?;

    // 3. Read response from client.
    let response = SshMessage::decode_from(&mut reader).await?;
    match response {
        SshMessage::ChannelOpenConfirmation { .. } => {
            // Client accepted — bridge raw bytes.
        }
        SshMessage::ChannelOpenFailure { .. } => {
            // Client rejected — drop Unix stream (implicit on return).
            return Ok(());
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected ChannelOpenConfirmation or ChannelOpenFailure, got {other:?}"
                ),
            ));
        }
    }

    // 4. Bridge raw bytes bidirectionally.
    let (unix_reader, unix_writer) = unix_stream.into_split();

    let q2u = tokio::spawn(super::relay(reader, unix_writer));
    let u2q = tokio::spawn(super::relay(unix_reader, writer));

    // Wait for both directions, handle errors.
    let (r1, r2) = tokio::join!(q2u, u2q);
    if let Ok(Err(e)) = r1 {
        tracing::warn!("relay quic→unix error: {e}");
    }
    if let Ok(Err(e)) = r2 {
        tracing::warn!("relay unix→quic error: {e}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::{codec::ChannelHeader, message::SshMessage};
    use genmeta_ssh3_proto::session::{Ssh3Transport, Ssh3TransportClient, Ssh3TransportServerShared, TransportError};
    use h3x::codec::{DecodeExt, EncodeExt};
    use h3x::varint::VarInt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use remoc::rtc::ServerShared;

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
        SshString(socket_path.to_owned()).encode_into(&mut buf)
            .await
            .unwrap();
        SshString(reserved_string.to_owned()).encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::try_from(reserved_uint32 as u64).unwrap())
            .await
            .unwrap();
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

        assert_eq!(socket_path, SshString("/var/run/app.sock".into()));
        assert_eq!(reserved_string, SshString("".into()));
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
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-streamlocal@openssh.com".into(),
            max_message_size: 1 << 20,
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
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
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
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-streamlocal@openssh.com".into(),
            max_message_size: 1 << 20,
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
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(
                    reason_code, SSH_OPEN_CONNECT_FAILED,
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
        let bytes = req.encode_to_bytes().await;
        let decoded = StreamlocalForwardRequest::decode_from_bytes(&bytes)
            .await
            .unwrap();
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
        let bytes = req.encode_to_bytes().await;
        let decoded = CancelStreamlocalForwardRequest::decode_from_bytes(&bytes)
            .await
            .unwrap();
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
        forwarder.start_listening(&sock_path, test_transport_client(), 1).await.unwrap();

        // Verify the listener is active by checking internal state.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(listeners.contains_key(&sock_path));
        }

        // Stop listening.
        let stopped = forwarder.stop_listening(&sock_path).await;
        assert!(stopped, "should return true when listener exists");

        // Verify it's gone.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(!listeners.contains_key(&sock_path));
        }

        // Stopping again should return false.
        let stopped_again = forwarder.stop_listening(&sock_path).await;
        assert!(!stopped_again, "should return false when listener doesn't exist");

        // Socket file should have been cleaned up by stop_listening.
        assert!(
            !std::path::Path::new(&sock_path).exists(),
            "socket file should be removed after stop"
        );
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
                42,
            )
            .await
            .unwrap();
        });

        // Client side: read ChannelHeader.
        let header = ChannelHeader::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(header.signal_value, CHANNEL_SIGNAL_VALUE);
        assert_eq!(header.conversation_id, 42);
        assert_eq!(header.channel_type, "forwarded-streamlocal@openssh.com");
        assert_eq!(header.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);

        // Client side: read request_data fields.
        let received_path = SshString::decode_from(&mut client_reader).await.unwrap();
        let reserved_string = SshString::decode_from(&mut client_reader).await.unwrap();

        assert_eq!(received_path, SshString(sock_path.clone()));
        assert_eq!(reserved_string, SshString("".into()));

        // Client side: send ChannelOpenConfirmation, then data, then close.
        let client_handle = tokio::spawn(async move {
            let mut client_writer = client_writer;
            let confirm = SshMessage::ChannelOpenConfirmation {
                max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            };
            confirm.encode_into(&mut client_writer).await.unwrap();

            // Send data through the channel (raw bytes, no wrapping).
            client_writer.write_all(b"hello-streamlocal").await.unwrap();
            drop(client_writer);
        });

        // Read the echoed data from the server side (comes via Unix echo → QUIC).
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello-streamlocal", "echoed data should be raw bytes");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();

        // Clean up socket file.
        let _ = std::fs::remove_file(&sock_path);
    }
}
