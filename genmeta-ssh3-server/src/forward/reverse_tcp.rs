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

use genmeta_ssh3_proto::{codec::ChannelHeader, codec::SshString, message::SshMessage};
use genmeta_ssh3_proto::session::{Ssh3Transport, Ssh3TransportClient};
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use snafu::Report;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::Instrument;

use crate::byte_channel::{ChannelReader, ChannelWriter};

/// Default maximum message size advertised in ChannelHeaders.
const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1 << 20; // 1 MiB

/// Signal value for channel headers (matching conversation.rs CHANNEL_SIGNAL_VALUE).
const CHANNEL_SIGNAL_VALUE: u32 = 0xaf3627e6;

// ---------------------------------------------------------------------------
// Request / response data structures
// ---------------------------------------------------------------------------

/// Decoded `tcpip-forward` request data: bind_address + bind_port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardRequest {
    pub bind_address: String,
    pub bind_port: u32,
}

impl TcpipForwardRequest {
    /// Encode into wire format: SshString(bind_address) + VarInt(bind_port).
    pub async fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString(self.bind_address.clone()).encode_into(&mut buf)
            .await
            .expect("vec write cannot fail");
        buf.encode_one(VarInt::try_from(self.bind_port as u64).unwrap())
            .await
            .expect("vec write cannot fail");
        buf
    }

    /// Decode from wire format bytes.
    pub async fn decode_from_bytes(data: &[u8]) -> io::Result<Self> {
        let mut reader = data;
        let bind_address = SshString::decode_from(&mut reader).await?;
        let bind_port: VarInt = reader.decode_one().await?;
        Ok(TcpipForwardRequest {
            bind_address: bind_address.0,
            bind_port: bind_port.into_inner() as u32,
        })
    }
}

/// Decoded `cancel-tcpip-forward` request data: bind_address + bind_port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelTcpipForwardRequest {
    pub bind_address: String,
    pub bind_port: u32,
}

impl CancelTcpipForwardRequest {
    /// Encode into wire format: SshString(bind_address) + VarInt(bind_port).
    pub async fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString(self.bind_address.clone()).encode_into(&mut buf)
            .await
            .expect("vec write cannot fail");
        buf.encode_one(VarInt::try_from(self.bind_port as u64).unwrap())
            .await
            .expect("vec write cannot fail");
        buf
    }

    /// Decode from wire format bytes.
    pub async fn decode_from_bytes(data: &[u8]) -> io::Result<Self> {
        let mut reader = data;
        let bind_address = SshString::decode_from(&mut reader).await?;
        let bind_port: VarInt = reader.decode_one().await?;
        Ok(CancelTcpipForwardRequest {
            bind_address: bind_address.0,
            bind_port: bind_port.into_inner() as u32,
        })
    }
}

/// Reply data for `tcpip-forward` when bind_port was 0 (ephemeral port allocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardReply {
    pub allocated_port: u32,
}

impl TcpipForwardReply {
    /// Encode into wire format: VarInt(allocated_port).
    pub async fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.encode_one(VarInt::try_from(self.allocated_port as u64).unwrap())
            .await
            .expect("vec write cannot fail");
        buf
    }

    /// Decode from wire format bytes.
    pub async fn decode_from_bytes(data: &[u8]) -> io::Result<Self> {
        let mut reader = data;
        let allocated_port: VarInt = reader.decode_one().await?;
        Ok(TcpipForwardReply {
            allocated_port: allocated_port.into_inner() as u32,
        })
    }
}

// ---------------------------------------------------------------------------
// forwarded-tcpip channel request_data encoding/decoding
// ---------------------------------------------------------------------------

/// Encode forwarded-tcpip channel request_data fields onto a stream.
///
/// Fields (RFC 4254 §7.2):
/// - connected_address: SshString
/// - connected_port: VarInt
/// - originator_address: SshString
/// - originator_port: VarInt
async fn encode_forwarded_tcpip_request_data<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    connected_addr: &str,
    connected_port: u16,
    originator_addr: &str,
    originator_port: u16,
) -> io::Result<()> {
    SshString(connected_addr.to_string()).encode_into(&mut *writer).await?;
    writer
        .encode_one(
            VarInt::try_from(connected_port as u64)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        )
        .await?;
    SshString(originator_addr.to_string()).encode_into(&mut *writer).await?;
    writer
        .encode_one(
            VarInt::try_from(originator_port as u64)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        )
        .await?;
    Ok(())
}

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
    listeners: Arc<Mutex<HashMap<(String, u16), tokio::task::JoinHandle<()>>>>,
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

        // Spawn the accept loop as a background task.
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp_stream, peer_addr)) => {
                        let transport = transport.clone();
                        let addr = bind_address_clone.clone();
                        let port = actual_port;
                        let conv_id = conversation_id;
                        tokio::spawn(async move {
                            match transport.open_channel(None).await {
                                Ok((from_remote_rx, to_remote_tx)) => {
                                    let reader = ChannelReader::new(from_remote_rx);
                                    let writer = ChannelWriter::new(to_remote_tx);
                                    if let Err(e) = handle_forwarded_tcpip_channel(
                                        reader, writer, tcp_stream,
                                        &addr, port,
                                        &peer_addr.ip().to_string(), peer_addr.port(),
                                        conv_id,
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
                    }
                    Err(e) => {
                        tracing::warn!(error = %Report::from_error(&e), "reverse-tcp accept error");
                        break;
                    }
                }
            }
        }.in_current_span());

        let mut listeners = self.listeners.lock().await;
        // If there was already a listener on this key, abort the old one.
        if let Some(old_handle) = listeners.insert(key, handle) {
            old_handle.abort();
        }

        Ok(actual_port)
    }

    /// Stop listening on `bind_address:bind_port`.
    ///
    /// Returns `true` if a listener was found and stopped, `false` otherwise.
    pub async fn stop_listening(&self, bind_address: &str, bind_port: u16) -> bool {
        let key = (bind_address.to_string(), bind_port);
        let mut listeners = self.listeners.lock().await;
        if let Some(handle) = listeners.remove(&key) {
            handle.abort();
            true
        } else {
            false
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
    mut reader: R,
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
    // 1. Write ChannelHeader.
        let header = ChannelHeader {
            signal_value: CHANNEL_SIGNAL_VALUE,
            conversation_id: conversation_id.into_inner(),
            channel_type: "forwarded-tcpip".to_string(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        };
    header.encode_into(&mut writer).await?;

    // 2. Write request_data fields.
    encode_forwarded_tcpip_request_data(
        &mut writer,
        connected_addr,
        connected_port,
        originator_addr,
        originator_port,
    )
    .await?;
    writer.flush().await?;

    // 3. Read response from client.
    let response = SshMessage::decode_from(&mut reader).await?;
    match response {
        SshMessage::ChannelOpenConfirmation { .. } => {
            // Client accepted — bridge raw bytes.
        }
        SshMessage::ChannelOpenFailure { .. } => {
            // Client rejected — drop TCP stream (implicit on return).
            return Ok(());
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected ChannelOpenConfirmation or ChannelOpenFailure, got {other:?}"),
            ));
        }
    }

    // 4. Bridge raw bytes bidirectionally.
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();

    let q2t = tokio::spawn(super::relay(reader, tcp_writer));
    let t2q = tokio::spawn(super::relay(tcp_reader, writer));

    // Wait for both directions, handle errors.
    let (r1, r2) = tokio::join!(q2t, t2q);
    if let Ok(Err(e)) = r1 {
        tracing::warn!(error = %Report::from_error(&e), "relay quic→tcp error");
    }
    if let Ok(Err(e)) = r2 {
        tracing::warn!(error = %Report::from_error(&e), "relay tcp→quic error");
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
    use genmeta_ssh3_proto::session::{Ssh3Transport, Ssh3TransportServerShared, TransportError};
    use h3x::codec::DecodeExt;
    use h3x::varint::VarInt;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
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

    // -------------------------------------------------------------------
    // Test 1: tcpip_forward_request_roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_request_roundtrip() {
        let req = TcpipForwardRequest {
            bind_address: "0.0.0.0".into(),
            bind_port: 8080,
        };
        let bytes = req.encode_to_bytes().await;
        let decoded = TcpipForwardRequest::decode_from_bytes(&bytes).await.unwrap();
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------
    // Test 2: tcpip_forward_request_hex_dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_request_hex_dump() {
        let req = TcpipForwardRequest {
            bind_address: "hi".into(),
            bind_port: 22,
        };
        let bytes = req.encode_to_bytes().await;
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
            bind_port: 3000,
        };
        let bytes = req.encode_to_bytes().await;
        let decoded = CancelTcpipForwardRequest::decode_from_bytes(&bytes).await.unwrap();
        assert_eq!(decoded, req);
    }

    // -------------------------------------------------------------------
    // Test 4: tcpip_forward_reply_roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_reply_roundtrip() {
        let reply = TcpipForwardReply {
            allocated_port: 49152,
        };
        let bytes = reply.encode_to_bytes().await;
        let decoded = TcpipForwardReply::decode_from_bytes(&bytes).await.unwrap();
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
                h3x::stream_id::StreamId(h3x::varint::VarInt::try_from(1u64).unwrap()),
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
        let stopped = forwarder.stop_listening("127.0.0.1", port).await;
        assert!(stopped, "should return true when listener exists");

        // Verify it's gone.
        {
            let listeners = forwarder.listeners.lock().await;
            assert!(!listeners.contains_key(&("127.0.0.1".to_string(), port)));
        }

        // Stopping again should return false.
        let stopped_again = forwarder.stop_listening("127.0.0.1", port).await;
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
                h3x::stream_id::StreamId(h3x::varint::VarInt::try_from(1u64).unwrap()),
            )
            .await
            .unwrap();
        let port2 = forwarder
            .start_listening(
                "127.0.0.1",
                0,
                test_transport_client(),
                h3x::stream_id::StreamId(h3x::varint::VarInt::try_from(2u64).unwrap()),
            )
            .await
            .unwrap();

        assert!(port1 > 0);
        assert!(port2 > 0);
        assert_ne!(port1, port2, "two dynamic allocations should yield different ports");

        // Clean up.
        forwarder.stop_listening("127.0.0.1", port1).await;
        forwarder.stop_listening("127.0.0.1", port2).await;
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
                h3x::stream_id::StreamId(h3x::varint::VarInt::try_from(42u64).unwrap()),
            )
            .await
            .unwrap();
        });

        // Client side: read ChannelHeader.
        let header = ChannelHeader::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(header.signal_value, CHANNEL_SIGNAL_VALUE);
        assert_eq!(header.conversation_id, 42);
        assert_eq!(header.channel_type, "forwarded-tcpip");
        assert_eq!(header.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);

        // Client side: read request_data fields.
        let connected_addr = SshString::decode_from(&mut client_reader).await.unwrap();
        let connected_port: VarInt = client_reader.decode_one().await.unwrap();
        let originator_addr = SshString::decode_from(&mut client_reader).await.unwrap();
        let originator_port: VarInt = client_reader.decode_one().await.unwrap();

        assert_eq!(connected_addr, SshString("192.168.1.100".into()));
        assert_eq!(connected_port.into_inner(), 80);
        assert_eq!(originator_addr, SshString("10.0.0.1".into()));
        assert_eq!(originator_port.into_inner(), 54321);

        // Client side: send ChannelOpenConfirmation, then data, then close.
        let client_handle = tokio::spawn(async move {
            let mut client_writer = client_writer;
            let confirm = SshMessage::ChannelOpenConfirmation {
                max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            };
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
                h3x::stream_id::StreamId(h3x::varint::VarInt::try_from(42u64).unwrap()),
            )
            .await
            .unwrap();
        });

        // Client side: read the header and request_data (drain them).
        let _header = ChannelHeader::decode_from(&mut client_reader).await.unwrap();
        let _connected_addr = SshString::decode_from(&mut client_reader).await.unwrap();
        let _connected_port: VarInt = client_reader.decode_one().await.unwrap();
        let _originator_addr = SshString::decode_from(&mut client_reader).await.unwrap();
        let _originator_port: VarInt = client_reader.decode_one().await.unwrap();

        // Client side: send ChannelOpenFailure to reject the channel.
        let failure = SshMessage::ChannelOpenFailure {
            reason_code: 1,
            description: "administratively prohibited".into(),
        };
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
