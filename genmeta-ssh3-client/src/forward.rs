//! Client-side TCP forwarding.
//!
//! Provides helpers for:
//! - **reverse TCP**: Client sends a `tcpip-forward` global request to ask
//!   the server to listen on a port and forward connections back.

use genmeta_ssh::{ForwardedTcpipRequest, TcpipForwardRequest};
use h3x::codec::EncodeExt;
use snafu::{ResultExt, Snafu};

/// Parsed request_data from a server-initiated `forwarded-tcpip` channel.
pub type ForwardedTcpipInfo = ForwardedTcpipRequest;

/// Error from encoding a forward request payload.
#[derive(Debug, Snafu)]
pub enum ForwardEncodeError {
    #[snafu(display("failed to encode forward request payload"))]
    EncodePayload { source: genmeta_ssh::forward::ForwardError },
}

/// Encode a `tcpip-forward` global request payload:
/// `SshString(bind_address) + VarInt(bind_port)`.
pub async fn encode_tcpip_forward_request(
    bind_address: &str,
    bind_port: u32,
) -> Result<Vec<u8>, ForwardEncodeError> {
    let mut buf = Vec::new();
    buf.encode_one(TcpipForwardRequest {
        bind_address: bind_address.to_owned().into(),
        bind_port: bind_port.into(),
    })
    .await
    .context(EncodePayloadSnafu)?;
    Ok(buf)
}

/// Encode a `cancel-tcpip-forward` global request payload:
/// `SshString(bind_address) + VarInt(bind_port)`.
pub async fn encode_cancel_tcpip_forward_request(
    bind_address: &str,
    bind_port: u32,
) -> Result<Vec<u8>, ForwardEncodeError> {
    encode_tcpip_forward_request(bind_address, bind_port).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh::TcpipForwardRequest;
    use h3x::codec::DecodeExt;

    #[tokio::test]
    async fn tcpip_forward_request_roundtrip() {
        let data = encode_tcpip_forward_request("0.0.0.0", 8080).await.unwrap();
        let decoded: TcpipForwardRequest = data.as_slice().decode_one().await.unwrap();
        assert_eq!(decoded.bind_address, "0.0.0.0");
        assert_eq!(decoded.bind_port, 8080);
    }

    #[tokio::test]
    async fn tcpip_forward_request_hex_dump() {
        let data = encode_tcpip_forward_request("hi", 22).await.unwrap();
        assert_eq!(data, vec![0x02, 0x68, 0x69, 0x16]);
    }
}
