//! Direct TCP forwarding channel (`direct-tcpip`).
//!
//! Implements RFC 4254 §7.2 — client-initiated TCP port forwarding.
//! After the [`ChannelHeader`] is read, the stream carries:
//!
//! 1. `dest_host` — [`SshString`]
//! 2. `dest_port` — [`VarInt`] (uint32)
//! 3. `originator_host` — [`SshString`]
//! 4. `originator_port` — [`VarInt`] (uint32)
//!
//! The server connects to `dest_host:dest_port`, sends
//! `ChannelOpenConfirmation(91)`, and bridges raw bytes between the QUIC
//! stream and the TCP socket. On TCP connect failure, sends
//! `ChannelOpenFailure(92)` with reason_code=2 (`SSH_OPEN_CONNECT_FAILED`).
//!
//! **CRITICAL**: After the confirmation, the QUIC stream carries raw bytes —
//! NOT wrapped in `SSH_MSG_CHANNEL_DATA(94)`.

use genmeta_ssh::{codec::ChannelHeader, codec::SshString, message::SshMessage, relay, DEFAULT_MAX_MESSAGE_SIZE};
use h3x::codec::{DecodeExt, EncodeExt};
use h3x::varint::VarInt;
use snafu::Report;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// SSH_OPEN_CONNECT_FAILED reason code (RFC 4254 §5.1).
const SSH_OPEN_CONNECT_FAILED: u64 = 2;

fn validate_port(raw_port: u64, field_name: &str) -> io::Result<u16> {
    u16::try_from(raw_port).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field_name} {raw_port} is out of range for a TCP port"),
        )
    })
}

/// Handle a `direct-tcpip` channel.
///
/// Reads the forwarding request fields from `reader`, attempts a TCP
/// connection to `dest_host:dest_port`, and bridges raw bytes between the
/// QUIC stream and the TCP socket.
pub async fn handle_direct_tcp<R, W>(
    _header: ChannelHeader,
    mut reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Parse request_data fields (RFC 4254 §7.2).
    let dest_host: SshString = reader.decode_one().await?;
    let dest_port: VarInt = reader.decode_one().await?;
    let _originator_host: SshString = reader.decode_one().await?;
    let _originator_port: VarInt = reader.decode_one().await?;

    let dest_port = match validate_port(dest_port.into_inner(), "destination port") {
        Ok(port) => port,
        Err(_) => {
            let failure = SshMessage::ChannelOpenFailure {
                reason_code: VarInt::from(SSH_OPEN_CONNECT_FAILED as u8),
                description: "destination port is out of range for a TCP port".into(),
            };
            writer.encode_one(&failure).await?;
            return Ok(());
        }
    };
    let addr = format!("{}:{}", dest_host.0, dest_port);

    // Attempt TCP connection.
    let tcp_stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(
                %addr,
                error = %Report::from_error(&e),
                "direct-tcpip connect failed"
            );
            let failure = SshMessage::ChannelOpenFailure {
                reason_code: VarInt::from(SSH_OPEN_CONNECT_FAILED as u8),
                description: "connect failed".into(),
            };
            writer.encode_one(&failure).await?;
            return Ok(());
        }
    };

    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: VarInt::from(DEFAULT_MAX_MESSAGE_SIZE as u32),
    };
    writer.encode_one(&confirm).await?;

    // Bridge raw bytes bidirectionally between QUIC stream and TCP socket.
    // We spawn two tasks for true concurrency — this avoids deadlocks that
    // can occur when both copy futures share a single task (join!/select!).
    let (tcp_reader, tcp_writer) = tcp_stream.into_split();

    let q2t = tokio::spawn(relay(reader, tcp_writer));
    let t2q = tokio::spawn(relay(tcp_reader, writer));

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


#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh::{codec::SshString, message::SshMessage};
    use h3x::codec::{DecodeFrom, EncodeExt, EncodeInto};
    use h3x::varint::VarInt;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Encode direct-tcpip request_data fields into bytes.
    async fn encode_request_data(
        dest_host: &str,
        dest_port: u32,
        originator_host: &str,
        originator_port: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString(dest_host.to_owned()).encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(dest_port))
            .await
            .unwrap();
        SshString(originator_host.to_owned()).encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(originator_port))
            .await
            .unwrap();
        buf
    }

    // -------------------------------------------------------------------
    // Test 1: request_data roundtrip — encode then decode, verify fields
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_tcp_request_data_roundtrip() {
        let data = encode_request_data("example.com", 8080, "192.168.1.1", 54321).await;

        let mut reader = &data[..];
        let dest_host = SshString::decode_from(&mut reader).await.unwrap();
        let dest_port: VarInt = reader.decode_one().await.unwrap();
        let originator_host = SshString::decode_from(&mut reader).await.unwrap();
        let originator_port: VarInt = reader.decode_one().await.unwrap();

        assert_eq!(dest_host, SshString("example.com".into()));
        assert_eq!(dest_port.into_inner(), 8080);
        assert_eq!(originator_host, SshString("192.168.1.1".into()));
        assert_eq!(originator_port.into_inner(), 54321);
    }

    // -------------------------------------------------------------------
    // Test 2: request_data hex dump — verify exact byte representation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_tcp_request_data_hex_dump() {
        let data = encode_request_data("hi", 80, "lo", 22).await;

        // dest_host "hi": varint(2)=0x02, b"hi"=[0x68, 0x69]
        // dest_port 80: varint(80) = 2-byte [0x40, 0x50] (80 >= 64)
        // originator_host "lo": varint(2)=0x02, b"lo"=[0x6c, 0x6f]
        // originator_port 22: varint(22) = 1-byte [0x16]
        assert_eq!(
            data,
            vec![
                0x02, 0x68, 0x69, // "hi"
                0x40, 0x50, // port 80
                0x02, 0x6c, 0x6f, // "lo"
                0x16, // port 22
            ]
        );
    }

    // -------------------------------------------------------------------
    // Test 3: full roundtrip — local TCP echo server, mock QUIC stream
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_tcp_roundtrip() {
        // Start a local TCP echo server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        // Build the request_data fields.
        let request_data = encode_request_data(
            "127.0.0.1",
            addr.port() as u32,
            "127.0.0.1",
            12345,
        )
        .await;

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        // client_writer → server_reader (QUIC read half)
        // server_writer → client_reader (QUIC write half)
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
            handle_direct_tcp(header, server_reader, server_writer)
                .await
                .unwrap();
        });

        // Read ChannelOpenConfirmation from the server.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match confirm {
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
                assert_eq!(max_message_size, VarInt::from(DEFAULT_MAX_MESSAGE_SIZE as u32));
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
    }

    // -------------------------------------------------------------------
    // Test 4: TCP connect failure → ChannelOpenFailure(92)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcp_connect_failure() {
        let request_data =
            encode_request_data("127.0.0.1", 1, "127.0.0.1", 11111).await;

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Write request_data then close.
        client_writer.write_all(&request_data).await.unwrap();
        drop(client_writer);

        // Server handles the channel.
        handle_direct_tcp(header, server_reader, server_writer)
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
                    reason_code, VarInt::from(SSH_OPEN_CONNECT_FAILED as u8),
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

    #[tokio::test]
    async fn out_of_range_port_is_rejected_instead_of_truncated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let overflow_port = listener.local_addr().unwrap().port() as u32 + (u16::MAX as u32) + 1;

        let request_data = encode_request_data("127.0.0.1", overflow_port, "127.0.0.1", 11111).await;

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        client_writer.write_all(&request_data).await.unwrap();
        drop(client_writer);

        handle_direct_tcp(header, server_reader, server_writer)
            .await
            .unwrap();

        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match msg {
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(reason_code, VarInt::from(SSH_OPEN_CONNECT_FAILED as u8));
                assert!(description.contains("out of range"), "unexpected description: {description}");
            }
            other => panic!("expected ChannelOpenFailure for out-of-range port, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 5: no SSH_MSG_CHANNEL_DATA wrapping in forwarded data
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn no_channel_data_wrapping() {
        // Start a TCP server that sends known data.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Send raw bytes and close.
            stream.write_all(b"raw-data-from-tcp").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let request_data = encode_request_data(
            "127.0.0.1",
            addr.port() as u32,
            "127.0.0.1",
            22222,
        )
        .await;

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        client_writer.write_all(&request_data).await.unwrap();
        drop(client_writer);

        let server_handle = tokio::spawn(async move {
            handle_direct_tcp(header, server_reader, server_writer)
                .await
                .unwrap();
        });

        // Read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(
            matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }),
            "expected ChannelOpenConfirmation, got {confirm:?}"
        );

        // Read the raw bytes from the QUIC stream. These should be the literal
        // TCP payload, NOT wrapped in SSH_MSG_CHANNEL_DATA(94).
        let mut received = Vec::new();
        client_reader.read_to_end(&mut received).await.unwrap();

        // If it were wrapped in ChannelData, the first bytes would be
        // varint(94) = [0x40, 0x5e]. Verify this is NOT the case.
        assert_eq!(received, b"raw-data-from-tcp");
        assert!(
            received.len() < 2 || received[..2] != [0x40, 0x5e],
            "data should NOT be wrapped in SSH_MSG_CHANNEL_DATA(94)"
        );

        server_handle.await.unwrap();
        tcp_server.await.unwrap();
    }
}
