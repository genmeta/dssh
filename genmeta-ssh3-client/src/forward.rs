//! Client-side TCP forwarding.
//!
//! Provides helpers for:
//! - **direct-tcpip**: Client opens a channel to forward TCP traffic through
//!   the SSH3 server to a remote destination.
//! - **reverse TCP**: Client sends a `tcpip-forward` global request to ask
//!   the server to listen on a port and forward connections back.
//! - **forwarded-tcpip**: Client accepts server-initiated channels for
//!   reverse-forwarded connections.

use genmeta_ssh3_proto::codec::{ChannelHeader, SshString};
use genmeta_ssh3_proto::message::SshMessage;
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::varint::VarInt;
use tokio::io::{self, AsyncRead, AsyncWrite};

/// Default maximum message size advertised in ChannelHeaders.
const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1 << 20; // 1 MiB

/// Signal value for channel headers (must match server's CHANNEL_SIGNAL_VALUE).
const CHANNEL_SIGNAL_VALUE: u32 = 0xaf3627e6;

// ---------------------------------------------------------------------------
// direct-tcpip
// ---------------------------------------------------------------------------

/// Encode the request_data fields for a `direct-tcpip` channel open (RFC 4254 §7.2):
///
/// - `SshString(dest_host)`
/// - `VarInt(dest_port)`
/// - `SshString(originator_host)`
/// - `VarInt(originator_port)`
pub async fn encode_direct_tcpip_request_data(
    dest_host: &str,
    dest_port: u32,
    originator_host: &str,
    originator_port: u32,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();

    SshString(dest_host.to_owned()).encode_into(&mut buf).await?;
    let dp = VarInt::try_from(dest_port as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(dp).await?;

    SshString(originator_host.to_owned()).encode_into(&mut buf).await?;
    let op = VarInt::try_from(originator_port as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(op).await?;

    Ok(buf)
}

/// Write a `direct-tcpip` channel header followed by request_data fields.
///
/// After calling this, the caller should read the server's response:
/// - `ChannelOpenConfirmation(91)` → success, bridge raw bytes
/// - `ChannelOpenFailure(92)` → connection failed
pub async fn write_direct_tcpip_channel_open<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    conversation_id: u64,
    dest_host: &str,
    dest_port: u32,
    originator_host: &str,
    originator_port: u32,
) -> io::Result<()> {
    let header = ChannelHeader {
        signal_value: CHANNEL_SIGNAL_VALUE,
        conversation_id,
        channel_type: "direct-tcpip".to_string(),
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    header.encode_into(&mut *writer).await?;

    // Write request_data fields inline on the stream (NOT as SshBytes — the
    // server reads them directly after the ChannelHeader).
    SshString(dest_host.to_owned()).encode_into(&mut *writer).await?;
    let dp = VarInt::try_from(dest_port as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    writer.encode_one(dp).await?;
    SshString(originator_host.to_owned()).encode_into(&mut *writer).await?;
    let op = VarInt::try_from(originator_port as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    writer.encode_one(op).await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// reverse TCP (tcpip-forward / cancel-tcpip-forward)
// ---------------------------------------------------------------------------

/// Encode a `tcpip-forward` global request data:
/// `SshString(bind_address) + VarInt(bind_port)`.
pub async fn encode_tcpip_forward_request(
    bind_address: &str,
    bind_port: u32,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    SshString(bind_address.to_owned()).encode_into(&mut buf).await?;
    let bp = VarInt::try_from(bind_port as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(bp).await?;
    Ok(buf)
}

/// Encode a `cancel-tcpip-forward` global request data:
/// `SshString(bind_address) + VarInt(bind_port)`.
pub async fn encode_cancel_tcpip_forward_request(
    bind_address: &str,
    bind_port: u32,
) -> io::Result<Vec<u8>> {
    // Same wire format as tcpip-forward.
    encode_tcpip_forward_request(bind_address, bind_port).await
}

/// Send a `tcpip-forward` GlobalRequest(80) to the server.
///
/// The server should reply with `RequestSuccess(81)` containing
/// `VarInt(allocated_port)` if `bind_port == 0`, or just `RequestSuccess`
/// with empty data.
pub async fn send_tcpip_forward_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    bind_address: &str,
    bind_port: u32,
) -> io::Result<()> {
    let data = encode_tcpip_forward_request(bind_address, bind_port).await?;
    SshMessage::GlobalRequest {
        request_type: "tcpip-forward".into(),
        want_reply: true,
        data,
    }.encode_into(writer)
    .await
}

/// Send a `cancel-tcpip-forward` GlobalRequest(80) to the server.
pub async fn send_cancel_tcpip_forward_request<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    bind_address: &str,
    bind_port: u32,
) -> io::Result<()> {
    let data = encode_cancel_tcpip_forward_request(bind_address, bind_port).await?;
    SshMessage::GlobalRequest {
        request_type: "cancel-tcpip-forward".into(),
        want_reply: true,
        data,
    }.encode_into(writer)
    .await
}

/// Parse the `RequestSuccess` reply to a `tcpip-forward` request.
///
/// When `bind_port == 0`, the reply data contains `VarInt(allocated_port)`.
/// When `bind_port != 0`, the reply data may be empty (allocated_port = bind_port).
pub async fn parse_tcpip_forward_reply(data: &[u8], original_bind_port: u32) -> io::Result<u32> {
    if data.is_empty() {
        Ok(original_bind_port)
    } else {
        let mut reader = data;
        let port: VarInt = reader.decode_one().await?;
        Ok(port.into_inner() as u32)
    }
}

// ---------------------------------------------------------------------------
// forwarded-tcpip channel acceptance
// ---------------------------------------------------------------------------

/// Parsed request_data from a server-initiated `forwarded-tcpip` channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedTcpipInfo {
    /// The address the server was listening on.
    pub connected_address: String,
    /// The port the server was listening on.
    pub connected_port: u32,
    /// The originator address of the incoming TCP connection.
    pub originator_address: String,
    /// The originator port of the incoming TCP connection.
    pub originator_port: u32,
}

/// Read the request_data fields from a `forwarded-tcpip` channel.
///
/// Called after the client has already read the [`ChannelHeader`] and verified
/// `channel_type == "forwarded-tcpip"`.
pub async fn read_forwarded_tcpip_info<R: AsyncRead + Send + Unpin>(
    reader: &mut R,
) -> io::Result<ForwardedTcpipInfo> {
    let connected_address = SshString::decode_from(&mut *reader).await?;
    let connected_port: VarInt = reader.decode_one().await?;
    let originator_address = SshString::decode_from(&mut *reader).await?;
    let originator_port: VarInt = reader.decode_one().await?;

    Ok(ForwardedTcpipInfo {
        connected_address: connected_address.0,
        connected_port: connected_port.into_inner() as u32,
        originator_address: originator_address.0,
        originator_port: originator_port.into_inner() as u32,
    })
}

/// Accept a server-initiated `forwarded-tcpip` channel by sending
/// `ChannelOpenConfirmation(91)`.
pub async fn accept_forwarded_channel<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
) -> io::Result<()> {
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: VarInt::from(DEFAULT_MAX_MESSAGE_SIZE as u32),
    };
    confirm.encode_into(writer).await
}

/// Reject a server-initiated `forwarded-tcpip` channel by sending
/// `ChannelOpenFailure(92)`.
pub async fn reject_forwarded_channel<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    reason_code: VarInt,
    description: &str,
) -> io::Result<()> {
    let failure = SshMessage::ChannelOpenFailure {
        reason_code,
        description: description.to_owned(),
    };
    failure.encode_into(writer).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::codec::{ChannelHeader, SshString};
    use genmeta_ssh3_proto::message::SshMessage;
    use genmeta_ssh3_server::forward::reverse_tcp::{
        TcpipForwardReply, TcpipForwardRequest,
    };
    use h3x::codec::DecodeExt;
    use h3x::varint::VarInt;
    use tokio::io::duplex;

    // -------------------------------------------------------------------
    // Test 1: direct-tcpip request_data roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_tcpip_request_data_roundtrip() {
        let data =
            encode_direct_tcpip_request_data("example.com", 8080, "192.168.1.1", 54321)
                .await
                .unwrap();

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
    // Test 2: direct-tcpip request_data hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn direct_tcpip_request_data_hex_dump() {
        let data =
            encode_direct_tcpip_request_data("hi", 80, "lo", 22)
                .await
                .unwrap();

        // dest_host "hi": varint(2)=0x02, b"hi"=[0x68, 0x69]
        // dest_port 80: varint(80) = 2-byte [0x40, 0x50] (80 >= 64)
        // originator_host "lo": varint(2)=0x02, b"lo"=[0x6c, 0x6f]
        // originator_port 22: varint(22) = 1-byte [0x16]
        assert_eq!(
            data,
            vec![
                0x02, 0x68, 0x69, // "hi"
                0x40, 0x50,       // port 80
                0x02, 0x6c, 0x6f, // "lo"
                0x16,             // port 22
            ]
        );
    }

    // -------------------------------------------------------------------
    // Test 3: write_direct_tcpip_channel_open produces correct header
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn write_direct_tcpip_channel_open_header() {
        let (mut writer, mut reader) = duplex(8192);
        write_direct_tcpip_channel_open(&mut writer, 42, "example.com", 80, "127.0.0.1", 12345)
            .await
            .unwrap();
        drop(writer);

        // Read the ChannelHeader
        let header = ChannelHeader::decode_from(&mut reader).await.unwrap();
        assert_eq!(header.signal_value, CHANNEL_SIGNAL_VALUE);
        assert_eq!(header.conversation_id, 42);
        assert_eq!(header.channel_type, "direct-tcpip");
        assert_eq!(header.max_message_size, DEFAULT_MAX_MESSAGE_SIZE);

        // Read request_data fields
        let dest_host = SshString::decode_from(&mut reader).await.unwrap();
        let dest_port: VarInt = reader.decode_one().await.unwrap();
        let originator_host = SshString::decode_from(&mut reader).await.unwrap();
        let originator_port: VarInt = reader.decode_one().await.unwrap();

        assert_eq!(dest_host, SshString("example.com".into()));
        assert_eq!(dest_port.into_inner(), 80);
        assert_eq!(originator_host, SshString("127.0.0.1".into()));
        assert_eq!(originator_port.into_inner(), 12345);
    }

    // -------------------------------------------------------------------
    // Test 4: tcpip-forward request encoding matches server's decoder
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_request_matches_server() {
        let data = encode_tcpip_forward_request("0.0.0.0", 8080).await.unwrap();

        // Verify with server's TcpipForwardRequest decoder
        let decoded = TcpipForwardRequest::decode_from_bytes(&data).await.unwrap();
        assert_eq!(decoded.bind_address, "0.0.0.0");
        assert_eq!(decoded.bind_port, 8080);
    }

    // -------------------------------------------------------------------
    // Test 5: tcpip-forward request hex dump
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn tcpip_forward_request_hex_dump() {
        let data = encode_tcpip_forward_request("hi", 22).await.unwrap();
        // "hi": varint(2)=0x02, b"hi"=[0x68, 0x69]
        // port 22: varint(22) = 1-byte [0x16]
        assert_eq!(data, vec![0x02, 0x68, 0x69, 0x16]);
    }

    // -------------------------------------------------------------------
    // Test 6: send_tcpip_forward_request produces GlobalRequest(80)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_tcpip_forward_global_request() {
        let (mut writer, mut reader) = duplex(8192);
        send_tcpip_forward_request(&mut writer, "0.0.0.0", 8080)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::GlobalRequest {
                request_type,
                want_reply,
                data,
            } => {
                assert_eq!(request_type, "tcpip-forward");
                assert!(want_reply);
                let decoded = TcpipForwardRequest::decode_from_bytes(&data).await.unwrap();
                assert_eq!(decoded.bind_address, "0.0.0.0");
                assert_eq!(decoded.bind_port, 8080);
            }
            other => panic!("expected GlobalRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 7: cancel-tcpip-forward request
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn send_cancel_tcpip_forward_global_request() {
        let (mut writer, mut reader) = duplex(8192);
        send_cancel_tcpip_forward_request(&mut writer, "127.0.0.1", 3000)
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::GlobalRequest {
                request_type,
                want_reply,
                data,
            } => {
                assert_eq!(request_type, "cancel-tcpip-forward");
                assert!(want_reply);
                let decoded = TcpipForwardRequest::decode_from_bytes(&data).await.unwrap();
                assert_eq!(decoded.bind_address, "127.0.0.1");
                assert_eq!(decoded.bind_port, 3000);
            }
            other => panic!("expected GlobalRequest, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 8: parse_tcpip_forward_reply with allocated port
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_tcpip_forward_reply_with_port() {
        let reply = TcpipForwardReply {
            allocated_port: 49152,
        };
        let bytes = reply.encode_to_bytes().await;
        let port = parse_tcpip_forward_reply(&bytes, 0).await.unwrap();
        assert_eq!(port, 49152);
    }

    // -------------------------------------------------------------------
    // Test 9: parse_tcpip_forward_reply with empty data
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_tcpip_forward_reply_empty() {
        let port = parse_tcpip_forward_reply(&[], 8080).await.unwrap();
        assert_eq!(port, 8080);
    }

    // -------------------------------------------------------------------
    // Test 10: read_forwarded_tcpip_info roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn read_forwarded_tcpip_info_roundtrip() {
        // Encode the fields the same way the server does
        let mut buf = Vec::new();
        SshString("192.168.1.100".into()).encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(80u8))
            .await
            .unwrap();
        SshString("10.0.0.1".into()).encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(54321u16))
            .await
            .unwrap();

        let mut reader = &buf[..];
        let info = read_forwarded_tcpip_info(&mut reader).await.unwrap();

        assert_eq!(info.connected_address, "192.168.1.100");
        assert_eq!(info.connected_port, 80);
        assert_eq!(info.originator_address, "10.0.0.1");
        assert_eq!(info.originator_port, 54321);
    }

    // -------------------------------------------------------------------
    // Test 11: accept_forwarded_channel sends ChannelOpenConfirmation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn accept_forwarded_channel_message() {
        let (mut writer, mut reader) = duplex(8192);
        accept_forwarded_channel(&mut writer).await.unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
                assert_eq!(max_message_size, VarInt::from(DEFAULT_MAX_MESSAGE_SIZE as u32));
            }
            other => panic!("expected ChannelOpenConfirmation, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Test 12: reject_forwarded_channel sends ChannelOpenFailure
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn reject_forwarded_channel_message() {
        let (mut writer, mut reader) = duplex(8192);
        reject_forwarded_channel(&mut writer, VarInt::from(1u8), "administratively prohibited")
            .await
            .unwrap();
        drop(writer);

        let msg = SshMessage::decode_from(&mut reader).await.unwrap();
        match msg {
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(reason_code, VarInt::from(1u8));
                assert_eq!(description, "administratively prohibited");
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }
    }
}
