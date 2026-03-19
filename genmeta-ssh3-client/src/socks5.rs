//! Client-side local SOCKS5 proxy server.
//!
//! Listens on a local TCP port, accepts SOCKS5 CONNECT requests from local
//! applications, and bridges them through SSH3 `direct-tcpip` channels to the
//! SSH3 server.
//!
//! The flow is:
//! ```text
//! Local App → SOCKS5 → Socks5ProxyServer → SSH3 direct-tcpip channel → SSH3 Server → Target
//! ```
//!
//! Only SOCKS5 with no authentication (method `0x00`) is supported.
//! Only the CONNECT command is supported — BIND and UDP ASSOCIATE are rejected.

use std::net::SocketAddr;
use std::sync::Arc;

use genmeta_ssh::SshMessage;
use h3x::codec::DecodeFrom;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::forward::write_direct_tcpip_channel_open;

// ---- SOCKS5 constants (RFC 1928) ----

const SOCKS5_VERSION: u8 = 0x05;

/// Authentication method: no authentication required.
const METHOD_NO_AUTH: u8 = 0x00;
/// Reply when no acceptable authentication method is found.
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 command: CONNECT.
const CMD_CONNECT: u8 = 0x01;

/// Address type: IPv4.
const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
const ATYP_IPV6: u8 = 0x04;

// SOCKS5 reply codes.
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// Copy all bytes from `reader` to `writer`, then shut down `writer`.
async fn relay<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(n)
}

/// A local SOCKS5 proxy server that forwards CONNECT requests through SSH3
/// `direct-tcpip` channels.
///
/// The `S` type parameter is a factory that produces a new QUIC stream
/// (read half + write half) for each SOCKS5 CONNECT request. In production,
/// this opens a new QUIC bidirectional stream on the SSH3 connection.
pub struct Socks5ProxyServer<S> {
    listener: TcpListener,
    conversation_id: u64,
    stream_factory: Arc<Mutex<S>>,
}

/// A factory trait for creating new QUIC streams for direct-tcpip channels.
///
/// Each SOCKS5 CONNECT request needs its own bidirectional stream to the server.
pub trait StreamFactory: Send + 'static {
    /// The read half of the stream.
    type Reader: AsyncRead + Send + Unpin + 'static;
    /// The write half of the stream.
    type Writer: AsyncWrite + Send + Unpin + 'static;

    /// Open a new bidirectional stream, returning `(reader, writer)`.
    fn open_stream(
        &mut self,
    ) -> impl std::future::Future<Output = io::Result<(Self::Reader, Self::Writer)>> + Send;
}

impl<S: StreamFactory> Socks5ProxyServer<S> {
    /// Create a new SOCKS5 proxy server bound to the given listener.
    pub fn new(listener: TcpListener, conversation_id: u64, stream_factory: S) -> Self {
        Self {
            listener,
            conversation_id,
            stream_factory: Arc::new(Mutex::new(stream_factory)),
        }
    }

    /// Returns the local address the proxy is listening on.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the proxy server, accepting connections until the listener is dropped.
    pub async fn run(self) -> io::Result<()> {
        loop {
            let (tcp_stream, _peer_addr) = self.listener.accept().await?;
            let factory = Arc::clone(&self.stream_factory);
            let conversation_id = self.conversation_id;

            tokio::spawn(async move {
                let (tcp_reader, tcp_writer) = tcp_stream.into_split();
                if let Err(e) =
                    handle_socks5_client(tcp_reader, tcp_writer, factory, conversation_id).await
                {
                    tracing::warn!(%e, "socks5 client handler failed");
                }
            });
        }
    }
}

/// Handle a single SOCKS5 client connection.
///
/// Performs SOCKS5 negotiation, opens a `direct-tcpip` channel via the stream
/// factory, and relays data bidirectionally.
pub async fn handle_socks5_client<R, W, S>(
    mut reader: R,
    mut writer: W,
    stream_factory: Arc<Mutex<S>>,
    conversation_id: u64,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: StreamFactory,
{
    // ---- Phase 1: Method negotiation ----
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS version: 0x{ver:02x}"),
        ));
    }

    let nmethods = reader.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    reader.read_exact(&mut methods).await?;

    if !methods.contains(&METHOD_NO_AUTH) {
        // No acceptable method — reply and close.
        writer
            .write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        writer.shutdown().await?;
        return Ok(());
    }

    // Reply: no auth required.
    writer
        .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
        .await?;

    // ---- Phase 2: CONNECT request ----
    let ver = reader.read_u8().await?;
    if ver != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS version in request: 0x{ver:02x}"),
        ));
    }

    let cmd = reader.read_u8().await?;
    let _rsv = reader.read_u8().await?; // reserved, must be 0x00
    let atyp = reader.read_u8().await?;

    // Parse destination address.
    let (dest_addr, dest_atyp_bytes) = match atyp {
        ATYP_IPV4 => {
            let mut addr_bytes = [0u8; 4];
            reader.read_exact(&mut addr_bytes).await?;
            let ip = std::net::Ipv4Addr::from(addr_bytes);
            (ip.to_string(), addr_bytes.to_vec())
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await?;
            let mut domain_bytes = vec![0u8; len as usize];
            reader.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes.clone())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            // Prepend the length byte for the reply.
            let mut atyp_bytes = vec![len];
            atyp_bytes.extend_from_slice(&domain_bytes);
            (domain, atyp_bytes)
        }
        ATYP_IPV6 => {
            let mut addr_bytes = [0u8; 16];
            reader.read_exact(&mut addr_bytes).await?;
            let ip = std::net::Ipv6Addr::from(addr_bytes);
            (ip.to_string(), addr_bytes.to_vec())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type: 0x{atyp:02x}"),
            ));
        }
    };

    // Read destination port (2 bytes, big-endian).
    let dest_port = reader.read_u16().await?;

    // Only CONNECT is supported.
    if cmd != CMD_CONNECT {
        send_reply(
            &mut writer,
            REP_COMMAND_NOT_SUPPORTED,
            atyp,
            &dest_atyp_bytes,
            dest_port,
        )
        .await?;
        writer.shutdown().await?;
        return Ok(());
    }

    // ---- Phase 3: Open direct-tcpip channel via SSH3 ----
    let (mut ch_reader, mut ch_writer) = {
        let mut factory = stream_factory.lock().await;
        factory.open_stream().await?
    };

    // Write the direct-tcpip channel open header + request_data.
    write_direct_tcpip_channel_open(
        &mut ch_writer,
        conversation_id,
        &dest_addr,
        dest_port as u32,
        "127.0.0.1",
        0,
    )
    .await?;

    // Read the server's response: ChannelOpenConfirmation or ChannelOpenFailure.
    let response = SshMessage::decode_from(&mut ch_reader).await?;
    match response {
        SshMessage::ChannelOpenConfirmation { .. } => {
            // Success — send SOCKS5 success reply.
            send_reply(&mut writer, REP_SUCCEEDED, atyp, &dest_atyp_bytes, dest_port).await?;
        }
        SshMessage::ChannelOpenFailure { .. } => {
            // Failure — send SOCKS5 connection refused reply.
            send_reply(
                &mut writer,
                REP_CONNECTION_REFUSED,
                atyp,
                &dest_atyp_bytes,
                dest_port,
            )
            .await?;
            writer.shutdown().await?;
            return Ok(());
        }
        other => {
            tracing::warn!(?other, "unexpected SSH3 message during channel open");
            send_reply(
                &mut writer,
                REP_GENERAL_FAILURE,
                atyp,
                &dest_atyp_bytes,
                dest_port,
            )
            .await?;
            writer.shutdown().await?;
            return Ok(());
        }
    }

    // ---- Phase 4: Bidirectional data relay ----
    // Raw bytes: SOCKS5 client ↔ QUIC channel (no ChannelData wrapping).
    let c2s = tokio::spawn(relay(reader, ch_writer));
    let s2c = tokio::spawn(relay(ch_reader, writer));

    let _ = c2s.await;
    let _ = s2c.await;

    Ok(())
}

/// Send a SOCKS5 reply with the given fields.
async fn send_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    atyp: u8,
    addr_bytes: &[u8],
    port: u16,
) -> io::Result<()> {
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00, atyp];
    reply.extend_from_slice(addr_bytes);
    reply.extend_from_slice(&port.to_be_bytes());
    writer.write_all(&reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::codec::EncodeInto;
    use genmeta_ssh::ChannelHeader;
    use genmeta_ssh::SshMessage;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    /// Default max message size for test responses.
    const TEST_MAX_MESSAGE_SIZE: u64 = 1 << 20;

    // -- Test stream factory --------------------------------------------------

    /// A test stream factory that returns pre-configured duplex stream pairs.
    /// The "server side" of each pair is sent over the channel for the test to
    /// interact with.
    struct TestStreamFactory {
        /// Receives (server_reader, server_writer) for each new stream.
        tx: mpsc::UnboundedSender<(DuplexStream, DuplexStream)>,
    }

    impl StreamFactory for TestStreamFactory {
        type Reader = DuplexStream;
        type Writer = DuplexStream;

        async fn open_stream(&mut self) -> io::Result<(Self::Reader, Self::Writer)> {
            let (client_reader, server_writer) = duplex(8192);
            let (server_reader, client_writer) = duplex(8192);
            self.tx
                .send((server_reader, server_writer))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "factory closed"))?;
            Ok((client_reader, client_writer))
        }
    }

    // -- SOCKS5 message builders -----------------------------------------------

    /// Build a SOCKS5 method negotiation message.
    fn socks5_greeting(methods: &[u8]) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, methods.len() as u8];
        buf.extend_from_slice(methods);
        buf
    }

    /// Build a SOCKS5 CONNECT request with IPv4 address.
    fn socks5_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    /// Build a SOCKS5 CONNECT request with domain name.
    fn socks5_connect_domain(domain: &str, port: u16) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN];
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    /// Build a SOCKS5 CONNECT request with IPv6 address.
    fn socks5_connect_ipv6(ip: [u8; 16], port: u16) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV6];
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    /// Simulate the SSH3 server side: read channel header + request_data, then
    /// respond with ChannelOpenConfirmation, then echo all data back.
    async fn simulate_server_echo(
        mut server_reader: DuplexStream,
        mut server_writer: DuplexStream,
    ) {
        // Read the channel header the client wrote.
        let header = ChannelHeader::decode_from(&mut server_reader).await.unwrap();
        assert_eq!(header.channel_type, "direct-tcpip");

        // Read request_data fields (dest_host, dest_port, originator_host, originator_port).
        use genmeta_ssh::SshString;
        use h3x::codec::DecodeExt;
        use h3x::varint::VarInt;
        let _dest_host = SshString::decode_from(&mut server_reader).await.unwrap();
        let _dest_port: VarInt = server_reader.decode_one().await.unwrap();
        let _orig_host = SshString::decode_from(&mut server_reader).await.unwrap();
        let _orig_port: VarInt = server_reader.decode_one().await.unwrap();

        // Send ChannelOpenConfirmation.
        SshMessage::ChannelOpenConfirmation {
            max_message_size: h3x::varint::VarInt::from(TEST_MAX_MESSAGE_SIZE as u32),
        }.encode_into(&mut server_writer)
        .await
        .unwrap();

        // Echo all data back.
        let (rd, wr) = (&mut server_reader, &mut server_writer);
        let _ = tokio::io::copy(rd, wr).await;
        let _ = server_writer.shutdown().await;
    }

    /// Simulate the SSH3 server side: read channel header, then respond with
    /// ChannelOpenFailure.
    async fn simulate_server_failure(
        mut server_reader: DuplexStream,
        mut server_writer: DuplexStream,
    ) {
        // Read the channel header.
        let _header = ChannelHeader::decode_from(&mut server_reader).await.unwrap();

        // Read request_data fields.
        use genmeta_ssh::SshString;
        use h3x::codec::DecodeExt;
        use h3x::varint::VarInt;
        let _dest_host = SshString::decode_from(&mut server_reader).await.unwrap();
        let _dest_port: VarInt = server_reader.decode_one().await.unwrap();
        let _orig_host = SshString::decode_from(&mut server_reader).await.unwrap();
        let _orig_port: VarInt = server_reader.decode_one().await.unwrap();

        // Send ChannelOpenFailure.
        SshMessage::ChannelOpenFailure {
            reason_code: h3x::varint::VarInt::from(2u8), // SSH_OPEN_CONNECT_FAILED
            description: "connection refused by server".to_string(),
        }.encode_into(&mut server_writer)
        .await
        .unwrap();

        let _ = server_writer.shutdown().await;
    }

    // -------------------------------------------------------------------
    // Test 1: SOCKS5 method negotiation (no-auth accepted)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_negotiation_no_auth() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        // Send greeting then an invalid version to end the handler.
        let greeting = socks5_greeting(&[METHOD_NO_AUTH]);
        let handle = tokio::spawn(async move {
            client_writer.write_all(&greeting).await.unwrap();
            // Send invalid version to cause error after greeting.
            client_writer.write_all(&[0xFF]).await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            let _ = handle_socks5_client(reader, writer, factory, 1).await;
        });

        // Read the greeting reply.
        let mut reply = [0u8; 2];
        client_reader.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 2: SOCKS5 method negotiation (no acceptable method → 0xFF)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_no_acceptable_method() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let handle = tokio::spawn(async move {
            // Only offer username/password (0x02) — no 0x00.
            client_writer
                .write_all(&socks5_greeting(&[0x02]))
                .await
                .unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Read reply — should indicate no acceptable method.
        let mut reply = [0u8; 2];
        client_reader.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]);

        handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 3: IPv4 CONNECT request parsing + relay
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_ipv4_relay() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv4([192, 168, 1, 1], 8080))
                .await
                .unwrap();
            client_writer.write_all(b"hello-ipv4").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 42)
                .await
                .unwrap();
        });

        // Simulate server side.
        let (server_reader, server_writer) = rx.recv().await.unwrap();
        tokio::spawn(simulate_server_echo(server_reader, server_writer));

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read CONNECT reply.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);
        assert_eq!(reply_header[2], 0x00); // RSV

        // Skip address + port in reply (IPv4=4+2, IPv6=16+2).
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 4 + 2];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 16 + 2];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_DOMAIN => {
                let len = client_reader.read_u8().await.unwrap();
                let mut skip = vec![0u8; len as usize + 2];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP in reply: 0x{other:02x}"),
        }

        // Read echoed data.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello-ipv4");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 4: IPv6 CONNECT request parsing + relay
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_ipv6_relay() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let ipv6_loopback: [u8; 16] = std::net::Ipv6Addr::LOCALHOST.octets();
        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv6(ipv6_loopback, 443))
                .await
                .unwrap();
            client_writer.write_all(b"hello-ipv6").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Simulate server side.
        let (server_reader, server_writer) = rx.recv().await.unwrap();
        tokio::spawn(simulate_server_echo(server_reader, server_writer));

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read CONNECT reply.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);

        // Skip address + port in reply.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_DOMAIN => {
                let len = client_reader.read_u8().await.unwrap();
                let mut skip = vec![0u8; len as usize + 2];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Read echoed data.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello-ipv6");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 5: Domain name CONNECT request parsing + relay
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_domain_relay() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_domain("example.com", 80))
                .await
                .unwrap();
            client_writer.write_all(b"hello-domain").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Simulate server side.
        let (server_reader, server_writer) = rx.recv().await.unwrap();
        tokio::spawn(simulate_server_echo(server_reader, server_writer));

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read CONNECT reply.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);

        // Skip address + port in reply.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_DOMAIN => {
                let len = client_reader.read_u8().await.unwrap();
                let mut skip = vec![0u8; len as usize + 2];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Read echoed data.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello-domain");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 6: Unsupported SOCKS5 command (BIND/UDP) → error
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_unsupported_command() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            // Send BIND request (CMD=0x02).
            let mut req = vec![SOCKS5_VERSION, 0x02, 0x00, ATYP_IPV4];
            req.extend_from_slice(&[127, 0, 0, 1]);
            req.extend_from_slice(&8080u16.to_be_bytes());
            client_writer.write_all(&req).await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read CONNECT reply — should be REP_COMMAND_NOT_SUPPORTED.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(
            reply_header[1], REP_COMMAND_NOT_SUPPORTED,
            "expected REP=0x07 (command not supported)"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 7: Connection failure → SOCKS5 error reply
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connection_failure() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv4([10, 0, 0, 1], 9999))
                .await
                .unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Simulate server side — respond with ChannelOpenFailure.
        let (server_reader, server_writer) = rx.recv().await.unwrap();
        tokio::spawn(simulate_server_failure(server_reader, server_writer));

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read CONNECT reply — should be REP_CONNECTION_REFUSED.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(
            reply_header[1], REP_CONNECTION_REFUSED,
            "expected REP=0x05 (connection refused)"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 8: Full lifecycle via TcpListener (SOCKS5 client → proxy → echo)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_full_lifecycle_tcp() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };

        // Bind the SOCKS5 proxy on an ephemeral port.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let proxy = Socks5ProxyServer::new(proxy_listener, 99, factory);
        let proxy_handle = tokio::spawn(async move {
            let _ = proxy.run().await;
        });

        // Spawn the simulated SSH3 server — handle one connection.
        let server_handle = tokio::spawn(async move {
            let (server_reader, server_writer) = rx.recv().await.unwrap();
            simulate_server_echo(server_reader, server_writer).await;
        });

        // Connect as a SOCKS5 client via TCP.
        let mut tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

        // Send SOCKS5 greeting.
        tcp.write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
            .await
            .unwrap();

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        tcp.read_exact(&mut greeting_reply).await.unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Send CONNECT request.
        tcp.write_all(&socks5_connect_ipv4([10, 20, 30, 40], 1234))
            .await
            .unwrap();

        // Read CONNECT reply.
        let mut reply_header = [0u8; 4];
        tcp.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);

        // Skip address + port in reply.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                tcp.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                tcp.read_exact(&mut skip).await.unwrap();
            }
            ATYP_DOMAIN => {
                let len = tcp.read_u8().await.unwrap();
                let mut skip = vec![0u8; len as usize + 2];
                tcp.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Send data and read echo.
        tcp.write_all(b"full-lifecycle-test").await.unwrap();
        tcp.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        tcp.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"full-lifecycle-test");

        server_handle.await.unwrap();
        proxy_handle.abort(); // Stop the proxy server loop.
    }

    // -------------------------------------------------------------------
    // Test 9: SOCKS5 reply hex dump — verify exact wire format
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_reply_hex_dump() {
        // Verify the exact bytes of a SOCKS5 success reply with IPv4 address.
        let mut buf = Vec::new();
        send_reply(&mut buf, REP_SUCCEEDED, ATYP_IPV4, &[127, 0, 0, 1], 8080)
            .await
            .unwrap();

        assert_eq!(
            buf,
            vec![
                0x05, 0x00, 0x00, 0x01, // VER, REP=succeeded, RSV, ATYP=IPv4
                127, 0, 0, 1,           // address
                0x1F, 0x90,             // port 8080 big-endian
            ]
        );

        // Verify a connection-refused reply with domain.
        let mut buf = Vec::new();
        let domain_bytes = &[3, b'f', b'o', b'o']; // len=3 + "foo"
        send_reply(&mut buf, REP_CONNECTION_REFUSED, ATYP_DOMAIN, domain_bytes, 443)
            .await
            .unwrap();

        assert_eq!(
            buf,
            vec![
                0x05, 0x05, 0x00, 0x03, // VER, REP=refused, RSV, ATYP=domain
                3, b'f', b'o', b'o',    // domain
                0x01, 0xBB,             // port 443 big-endian
            ]
        );
    }

    // -------------------------------------------------------------------
    // Test 10: UDP ASSOCIATE (CMD=0x03) → command not supported
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_udp_associate_rejected() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            // Send UDP ASSOCIATE request (CMD=0x03).
            let mut req = vec![SOCKS5_VERSION, 0x03, 0x00, ATYP_IPV4];
            req.extend_from_slice(&[0, 0, 0, 0]);
            req.extend_from_slice(&0u16.to_be_bytes());
            client_writer.write_all(&req).await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();
        assert_eq!(greeting_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read CONNECT reply — should be REP_COMMAND_NOT_SUPPORTED.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(
            reply_header[1], REP_COMMAND_NOT_SUPPORTED,
            "expected REP=0x07 (command not supported) for UDP ASSOCIATE"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 11: Verify no ChannelData wrapping in relay
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_no_channel_data_wrapping() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let factory = TestStreamFactory { tx };
        let factory = Arc::new(Mutex::new(factory));

        let (mut client_writer, reader) = duplex(8192);
        let (writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv4([1, 2, 3, 4], 80))
                .await
                .unwrap();
            client_writer.write_all(b"raw-bytes-test").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5_client(reader, writer, factory, 1)
                .await
                .unwrap();
        });

        // Simulate server: echo back.
        let (server_reader, server_writer) = rx.recv().await.unwrap();
        tokio::spawn(simulate_server_echo(server_reader, server_writer));

        // Read greeting reply.
        let mut greeting_reply = [0u8; 2];
        client_reader
            .read_exact(&mut greeting_reply)
            .await
            .unwrap();

        // Read and skip CONNECT reply.
        let mut reply_header = [0u8; 4];
        client_reader
            .read_exact(&mut reply_header)
            .await
            .unwrap();
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_DOMAIN => {
                let len = client_reader.read_u8().await.unwrap();
                let mut skip = vec![0u8; len as usize + 2];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Read relayed data.
        let mut received = Vec::new();
        client_reader.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"raw-bytes-test");

        // Verify no ChannelData wrapping (varint(94) = [0x40, 0x5e]).
        assert!(
            received.len() < 2 || received[..2] != [0x40, 0x5e],
            "data should NOT be wrapped in SSH_MSG_CHANNEL_DATA(94)"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }
}
