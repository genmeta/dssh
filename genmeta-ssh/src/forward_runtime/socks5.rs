//! SOCKS5 proxy channel handler (RFC 1928).
//!
//! When a client opens a `socks5` channel, the negotiation happens directly on
//! the raw QUIC stream:
//!
//! 1. Method negotiation (no-auth only).
//! 2. CONNECT request with IPv4 / IPv6 / domain destination.
//! 3. TCP connect, reply, then bidirectional data relay.

use crate::forward_runtime::relay;
use snafu::Snafu;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS5_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum Socks5Error {
    #[snafu(display("SOCKS5 protocol I/O failed"))]
    Io { source: std::io::Error },

    #[snafu(display("unsupported SOCKS version: 0x{version:02x}"))]
    UnsupportedVersion { version: u8 },

    #[snafu(display("unsupported address type: 0x{atyp:02x}"))]
    UnsupportedAddressType { atyp: u8 },

    #[snafu(display("domain name is not valid UTF-8"))]
    InvalidDomain { source: std::string::FromUtf8Error },

    #[snafu(display("relay task panicked"))]
    RelayJoin { source: tokio::task::JoinError },
}

/// Handle a `socks5` channel.
///
/// Performs SOCKS5 negotiation, connects to the requested TCP destination,
/// and relays raw bytes bidirectionally.
pub async fn handle_socks5<R, W>(mut reader: R, mut writer: W) -> Result<(), Socks5Error>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Phase 1: Method negotiation
    let ver = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })?;
    if ver != SOCKS5_VERSION {
        return Err(Socks5Error::UnsupportedVersion { version: ver });
    }

    let nmethods = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })? as usize;
    let mut methods = vec![0u8; nmethods];
    reader
        .read_exact(&mut methods)
        .await
        .map_err(|e| Socks5Error::Io { source: e })?;

    if !methods.contains(&METHOD_NO_AUTH) {
        writer
            .write_all(&[SOCKS5_VERSION, METHOD_NO_ACCEPTABLE])
            .await
            .map_err(|e| Socks5Error::Io { source: e })?;
        writer.shutdown().await.map_err(|e| Socks5Error::Io { source: e })?;
        return Ok(());
    }

    writer
        .write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
        .await
        .map_err(|e| Socks5Error::Io { source: e })?;

    // Phase 2: CONNECT request
    let ver = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })?;
    if ver != SOCKS5_VERSION {
        return Err(Socks5Error::UnsupportedVersion { version: ver });
    }

    let cmd = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })?;
    let _rsv = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })?;
    let atyp = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })?;

    let (dest_addr, dest_atyp_bytes) = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| Socks5Error::Io { source: e })?;
            (Ipv4Addr::from(buf).to_string(), buf.to_vec())
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await.map_err(|e| Socks5Error::Io { source: e })? as usize;
            let mut buf = vec![0u8; len];
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| Socks5Error::Io { source: e })?;
            let domain =
                String::from_utf8(buf.clone()).map_err(|e| Socks5Error::InvalidDomain { source: e })?;
            let mut atyp_bytes = vec![len as u8];
            atyp_bytes.extend_from_slice(&buf);
            (domain, atyp_bytes)
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| Socks5Error::Io { source: e })?;
            (Ipv6Addr::from(buf).to_string(), buf.to_vec())
        }
        _ => return Err(Socks5Error::UnsupportedAddressType { atyp }),
    };

    let dest_port = reader.read_u16().await.map_err(|e| Socks5Error::Io { source: e })?;

    if cmd != CMD_CONNECT {
        send_reply(&mut writer, REP_COMMAND_NOT_SUPPORTED, atyp, &dest_atyp_bytes, dest_port)
            .await?;
        writer.shutdown().await.map_err(|e| Socks5Error::Io { source: e })?;
        return Ok(());
    }

    // Phase 3: TCP connect
    let addr = format!("{dest_addr}:{dest_port}");
    let tcp_stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%addr, error = %snafu::Report::from_error(&e), "socks5 connect failed");
            send_reply(&mut writer, REP_CONNECTION_REFUSED, atyp, &dest_atyp_bytes, dest_port)
                .await?;
            writer.shutdown().await.map_err(|e| Socks5Error::Io { source: e })?;
            return Ok(());
        }
    };

    let local_addr = tcp_stream
        .local_addr()
        .map_err(|e| Socks5Error::Io { source: e })?;
    send_reply_with_bound_addr(&mut writer, REP_SUCCEEDED, &local_addr).await?;

    // Phase 4: Bidirectional relay
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();
    let q2t = tokio::spawn(relay(reader, tcp_writer));
    let t2q = tokio::spawn(relay(tcp_reader, writer));

    let (r1, r2) = tokio::join!(q2t, t2q);
    r1.map_err(|e| Socks5Error::RelayJoin { source: e })?
        .map_err(|e| Socks5Error::Io { source: e })?;
    r2.map_err(|e| Socks5Error::RelayJoin { source: e })?
        .map_err(|e| Socks5Error::Io { source: e })?;

    Ok(())
}

async fn send_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    atyp: u8,
    addr_bytes: &[u8],
    port: u16,
) -> Result<(), Socks5Error> {
    let mut reply = vec![SOCKS5_VERSION, rep, 0x00, atyp];
    reply.extend_from_slice(addr_bytes);
    reply.extend_from_slice(&port.to_be_bytes());
    writer
        .write_all(&reply)
        .await
        .map_err(|e| Socks5Error::Io { source: e })
}

async fn send_reply_with_bound_addr<W: AsyncWrite + Unpin>(
    writer: &mut W,
    rep: u8,
    addr: &SocketAddr,
) -> Result<(), Socks5Error> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut reply = vec![SOCKS5_VERSION, rep, 0x00, ATYP_IPV4];
            reply.extend_from_slice(&v4.ip().octets());
            reply.extend_from_slice(&v4.port().to_be_bytes());
            writer
                .write_all(&reply)
                .await
                .map_err(|e| Socks5Error::Io { source: e })
        }
        SocketAddr::V6(v6) => {
            let mut reply = vec![SOCKS5_VERSION, rep, 0x00, ATYP_IPV6];
            reply.extend_from_slice(&v6.ip().octets());
            reply.extend_from_slice(&v6.port().to_be_bytes());
            writer
                .write_all(&reply)
                .await
                .map_err(|e| Socks5Error::Io { source: e })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn socks5_greeting(methods: &[u8]) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, methods.len() as u8];
        buf.extend_from_slice(methods);
        buf
    }

    fn socks5_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4];
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    fn socks5_connect_domain(domain: &str, port: u16) -> Vec<u8> {
        let mut buf = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN];
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    #[tokio::test]
    async fn socks5_ipv4_echo_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = s.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, mut client_rd) = duplex(8192);

        let client = tokio::spawn(async move {
            // Greeting
            client_wr
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            // Connect
            client_wr
                .write_all(&socks5_connect_ipv4([127, 0, 0, 1], port))
                .await
                .unwrap();
            // Payload
            client_wr.write_all(b"socks-test").await.unwrap();
            drop(client_wr);
        });

        let handler = tokio::spawn(handle_socks5(server_rd, server_wr));

        // Read method reply
        let mut method_reply = [0u8; 2];
        client_rd.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS5_VERSION, METHOD_NO_AUTH]);

        // Read connect reply (VER, REP, RSV, ATYP, ADDR, PORT)
        let ver = client_rd.read_u8().await.unwrap();
        assert_eq!(ver, SOCKS5_VERSION);
        let rep = client_rd.read_u8().await.unwrap();
        assert_eq!(rep, REP_SUCCEEDED);
        let _rsv = client_rd.read_u8().await.unwrap();
        let atyp = client_rd.read_u8().await.unwrap();
        // Skip address bytes + port
        match atyp {
            ATYP_IPV4 => {
                let mut skip = [0u8; 4 + 2];
                client_rd.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 16 + 2];
                client_rd.read_exact(&mut skip).await.unwrap();
            }
            _ => panic!("unexpected atyp {atyp}"),
        }

        // Read echoed data
        let mut echoed = Vec::new();
        client_rd.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"socks-test");

        client.await.unwrap();
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_refused() {
        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, mut client_rd) = duplex(8192);

        client_wr
            .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
            .await
            .unwrap();
        client_wr
            .write_all(&socks5_connect_ipv4([127, 0, 0, 1], 1))
            .await
            .unwrap();
        drop(client_wr);

        handle_socks5(server_rd, server_wr).await.unwrap();

        // Method reply
        let mut method_reply = [0u8; 2];
        client_rd.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply[1], METHOD_NO_AUTH);

        // Connect reply should be refused
        let _ver = client_rd.read_u8().await.unwrap();
        let rep = client_rd.read_u8().await.unwrap();
        assert_eq!(rep, REP_CONNECTION_REFUSED);
    }

    #[tokio::test]
    async fn socks5_no_acceptable_method() {
        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, mut client_rd) = duplex(8192);

        // Offer only method 0x02 (username/password, not supported)
        client_wr
            .write_all(&socks5_greeting(&[0x02]))
            .await
            .unwrap();
        drop(client_wr);

        handle_socks5(server_rd, server_wr).await.unwrap();

        let mut reply = [0u8; 2];
        client_rd.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS5_VERSION, METHOD_NO_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn socks5_domain_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = s.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, mut client_rd) = duplex(8192);

        let client = tokio::spawn(async move {
            client_wr
                .write_all(&socks5_greeting(&[METHOD_NO_AUTH]))
                .await
                .unwrap();
            client_wr
                .write_all(&socks5_connect_domain("localhost", port))
                .await
                .unwrap();
            client_wr.write_all(b"domain-test").await.unwrap();
            drop(client_wr);
        });

        let handler = tokio::spawn(handle_socks5(server_rd, server_wr));

        // Skip method reply
        let mut skip = [0u8; 2];
        client_rd.read_exact(&mut skip).await.unwrap();

        // Read connect reply header
        let ver = client_rd.read_u8().await.unwrap();
        assert_eq!(ver, SOCKS5_VERSION);
        let rep = client_rd.read_u8().await.unwrap();
        assert_eq!(rep, REP_SUCCEEDED);
        let _rsv = client_rd.read_u8().await.unwrap();
        let atyp = client_rd.read_u8().await.unwrap();
        match atyp {
            ATYP_IPV4 => {
                let mut skip = [0u8; 6];
                client_rd.read_exact(&mut skip).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut skip = [0u8; 18];
                client_rd.read_exact(&mut skip).await.unwrap();
            }
            _ => panic!("unexpected atyp {atyp}"),
        }

        let mut echoed = Vec::new();
        client_rd.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"domain-test");

        client.await.unwrap();
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }
}
