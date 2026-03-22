//! SOCKS5 proxy channel (`socks5`).
//!
//! Implements RFC 1928 — SOCKS Protocol Version 5 (no authentication).
//! After the [`ChannelHeader`] is read by the dispatch layer, the SOCKS5
//! negotiation happens directly on the raw QUIC stream:
//!
//! 1. **Method negotiation**: client sends `VER(0x05) NMETHODS METHODS`,
//!    server replies `VER(0x05) METHOD(0x00)` (no auth required).
//! 2. **CONNECT request**: client sends `VER(0x05) CMD(0x01) RSV(0x00) ATYP DST.ADDR DST.PORT`,
//!    server establishes TCP connection and replies with success/failure.
//! 3. **Data relay**: after successful handshake, raw bytes are bridged
//!    bidirectionally between the QUIC stream and the TCP socket.

use genmeta_ssh::{ChannelHeader, relay};
use snafu::Report;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

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
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// Handle a `socks5` channel.
///
/// Performs SOCKS5 negotiation on the QUIC stream, connects to the
/// requested destination via TCP, and bridges raw bytes bidirectionally.
pub async fn handle_socks5<R, W>(
    _header: ChannelHeader,
    mut reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
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
        writer.write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]).await?;
        writer.shutdown().await?;
        return Ok(());
    }

    // Reply: no auth required.
    writer.write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH]).await?;

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
            let ip = Ipv4Addr::from(addr_bytes);
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
            let ip = Ipv6Addr::from(addr_bytes);
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
        send_reply(&mut writer, REP_COMMAND_NOT_SUPPORTED, atyp, &dest_atyp_bytes, dest_port)
            .await?;
        writer.shutdown().await?;
        return Ok(());
    }

    // ---- Phase 3: TCP connect ----
    let addr = format!("{dest_addr}:{dest_port}");
    let tcp_stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(
                %addr,
                error = %Report::from_error(&e),
                "socks5 connect failed"
            );
            send_reply(&mut writer, REP_CONNECTION_REFUSED, atyp, &dest_atyp_bytes, dest_port)
                .await?;
            writer.shutdown().await?;
            return Ok(());
        }
    };

    // Build reply with the bound address of the TCP socket.
    let local_addr = tcp_stream.local_addr()?;
    send_reply_with_bound_addr(&mut writer, REP_SUCCEEDED, &local_addr).await?;

    // ---- Phase 4: Bidirectional data relay ----
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();

    let q2t = tokio::spawn(relay(reader, tcp_writer));
    let t2q = tokio::spawn(relay(tcp_reader, writer));

    // Wait for both directions, handle errors.
    let (r1, r2) = tokio::join!(q2t, t2q);
    if let Ok(Err(e)) = r1 {
        tracing::warn!(error = %Report::from_error(&e), "relay quic→socks error");
    }
    if let Ok(Err(e)) = r2 {
        tracing::warn!(error = %Report::from_error(&e), "relay socks→quic error");
    }

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

/// Send a SOCKS5 success/failure reply using the actual bound socket address.
async fn send_reply_with_bound_addr<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    addr: &SocketAddr,
) -> io::Result<()> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut reply = vec![SOCKS5_VERSION, rep, 0x00, ATYP_IPV4];
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
            writer.write_all(&reply).await?;
        }
        SocketAddr::V6(v6) => {
            let mut reply = vec![SOCKS5_VERSION, rep, 0x00, ATYP_IPV6];
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
            writer.write_all(&reply).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh::{ChannelHeader, ChannelOpenBody};
    use h3x::stream_id::StreamId;
    use h3x::varint::VarInt;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn test_header() -> ChannelHeader {
        ChannelHeader {
            session_id: StreamId::try_from(1u64).unwrap(),
            max_message_size: VarInt::from(1u32 << 20),
            body: ChannelOpenBody::Socks5,
        }
    }

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

    // -------------------------------------------------------------------
    // Test 1: socks5_negotiation_no_auth — [0x05, 0x01, 0x00] → [0x05, 0x00]
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_negotiation_no_auth() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Client sends greeting with METHOD_NO_AUTH only, then a CONNECT to
        // a port that won't exist (we only care about the greeting reply).
        let greeting = socks5_greeting(&[METHOD_NO_AUTH]);

        let client_handle = tokio::spawn(async move {
            client_writer.write_all(&greeting).await.unwrap();
            // Send an invalid version to cause the server to error out after greeting.
            // We just want to verify the greeting reply.
            client_writer.write_all(&[0xFF]).await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            let _ = handle_socks5(test_header(), server_reader, server_writer).await;
        });

        // Read the greeting reply.
        let mut reply = [0u8; 2];
        client_reader.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 2: socks5_connect_ipv4 — full lifecycle with IPv4 to echo server
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_ipv4_echo() {
        // Start a local TCP echo server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let port = addr.port();
        let client_handle = tokio::spawn(async move {
            // Send greeting.
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            // Send CONNECT request.
            client_writer
                .write_all(&socks5_connect_ipv4([127, 0, 0, 1], port))
                .await
                .unwrap();
            // Send payload data.
            client_writer.write_all(b"hello-socks5").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5(test_header(), server_reader, server_writer)
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

        // Read CONNECT reply header (VER + REP + RSV + ATYP).
        let mut reply_header = [0u8; 4];
        client_reader.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);
        assert_eq!(reply_header[2], 0x00); // RSV

        // Skip bound address + port based on ATYP.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 4 + 2]; // 4 addr + 2 port
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 16 + 2]; // 16 addr + 2 port
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP in reply: 0x{other:02x}"),
        }

        // Read echoed data.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello-socks5");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 3: socks5_connect_domain — CONNECT with ATYP=0x03 (domain name)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_domain_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let port = addr.port();
        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_domain("localhost", port))
                .await
                .unwrap();
            client_writer.write_all(b"domain-test").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5(test_header(), server_reader, server_writer)
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

        // Read CONNECT reply header.
        let mut reply_header = [0u8; 4];
        client_reader.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);

        // Skip bound address + port.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Read echoed data.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"domain-test");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 4: socks5_connect_ipv6 — CONNECT with IPv6 to local echo server
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_ipv6_echo() {
        // Try to bind IPv6 loopback — skip if not available.
        let listener = match TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => {
                eprintln!("IPv6 loopback not available, skipping test");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();

        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let port = addr.port();
        let ipv6_loopback: [u8; 16] = Ipv6Addr::LOCALHOST.octets();

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv6(ipv6_loopback, port))
                .await
                .unwrap();
            client_writer.write_all(b"ipv6-test").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5(test_header(), server_reader, server_writer)
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

        // Read CONNECT reply header.
        let mut reply_header = [0u8; 4];
        client_reader.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(reply_header[1], REP_SUCCEEDED);

        // Skip bound address + port.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Read echoed data.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"ipv6-test");

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 5: socks5_connect_refused — TCP connect fails → REP=0x05
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_connect_refused() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv4([127, 0, 0, 1], 1))
                .await
                .unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5(test_header(), server_reader, server_writer)
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

        // Read CONNECT reply — should be REP_CONNECTION_REFUSED.
        let mut reply_header = [0u8; 4];
        client_reader.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(
            reply_header[1], REP_CONNECTION_REFUSED,
            "expected REP=0x05 (connection refused)"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 6: socks5_unsupported_cmd — BIND (CMD=0x02) → REP=0x07
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_unsupported_cmd() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

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
            handle_socks5(test_header(), server_reader, server_writer)
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
        client_reader.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[0], SOCKS5_VERSION);
        assert_eq!(
            reply_header[1], REP_COMMAND_NOT_SUPPORTED,
            "expected REP=0x07 (command not supported)"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 7: socks5_data_relay — verify raw bytes relayed after handshake
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_data_relay() {
        // Start a TCP server that sends known data, then echoes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Send a greeting first.
            stream.write_all(b"server-hello").await.unwrap();
            // Read client data and echo it back.
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let port = addr.port();
        let client_handle = tokio::spawn(async move {
            // SOCKS5 handshake.
            client_writer
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_writer
                .write_all(&socks5_connect_ipv4([127, 0, 0, 1], port))
                .await
                .unwrap();
            // Send raw data after handshake.
            client_writer.write_all(b"client-hello").await.unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5(test_header(), server_reader, server_writer)
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

        // Read CONNECT reply header.
        let mut reply_header = [0u8; 4];
        client_reader.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[1], REP_SUCCEEDED);

        // Skip bound address + port.
        match reply_header[3] {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_reader.read_exact(&mut skip).await.unwrap();
            }
            other => panic!("unexpected ATYP: 0x{other:02x}"),
        }

        // Read relayed data — should be raw bytes from TCP server, NOT
        // wrapped in SSH_MSG_CHANNEL_DATA.
        let mut received = Vec::new();
        client_reader.read_to_end(&mut received).await.unwrap();

        // Should contain "server-hello" followed by echoed "client-hello".
        assert_eq!(received, b"server-helloclient-hello");

        // Verify no ChannelData wrapping (varint(94) = [0x40, 0x5e]).
        assert!(
            received.len() < 2 || received[..2] != [0x40, 0x5e],
            "data should NOT be wrapped in SSH_MSG_CHANNEL_DATA(94)"
        );

        client_handle.await.unwrap();
        server_handle.await.unwrap();
        tcp_server.await.unwrap();
    }

    // -------------------------------------------------------------------
    // Test 8: socks5_no_acceptable_method — client has no METHOD_NO_AUTH
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn socks5_no_acceptable_method() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            // Only offer username/password (0x02) — no 0x00.
            client_writer
                .write_all(&socks5_greeting(&[0x02]))
                .await
                .unwrap();
            drop(client_writer);
        });

        let server_handle = tokio::spawn(async move {
            handle_socks5(test_header(), server_reader, server_writer)
                .await
                .unwrap();
        });

        // Read reply — should indicate no acceptable method.
        let mut reply = [0u8; 2];
        client_reader.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]);

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }
}
