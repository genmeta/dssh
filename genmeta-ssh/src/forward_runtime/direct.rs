//! Server-side direct forwarding channel handlers.
//!
//! Implements `direct-tcpip` (RFC 4254 §7.2) and
//! `direct-streamlocal@openssh.com` (OpenSSH streamlocal extension).
//!
//! After the [`ChannelHeader`] is consumed by the dispatch layer, the handler
//! reads destination info from the stream, connects to the target, sends
//! `ChannelOpenConfirmation` or `ChannelOpenFailure`, then relays raw bytes
//! bidirectionally.
//!
//! **After confirmation, the QUIC stream carries raw bytes — NOT wrapped in
//! `SSH_MSG_CHANNEL_DATA`.**

use crate::{
    channel::reason_code,
    codec::SshString,
    conversation::{
        PendingChannel, WriteChannelOpenConfirmationError, WriteChannelOpenFailureError,
    },
    forward_runtime::relay,
};
use h3x::{codec::DecodeExt, varint::VarInt};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum DirectForwardError {
    #[snafu(display("failed to decode request field"))]
    Decode { source: crate::codec::CodecError },

    #[snafu(display("failed to decode varint field"))]
    DecodeVarint { source: std::io::Error },

    #[snafu(display("destination port {raw_port} exceeds u16 range"))]
    PortOverflow { raw_port: u64 },

    #[snafu(display("failed to send channel open confirmation"))]
    Accept {
        source: WriteChannelOpenConfirmationError,
    },

    #[snafu(display("failed to send channel open failure"))]
    Reject {
        source: WriteChannelOpenFailureError,
    },

    #[snafu(display("TCP connect to {addr} failed"))]
    TcpConnect {
        addr: String,
        source: std::io::Error,
    },

    #[snafu(display("Unix socket connect to {path} failed"))]
    UnixConnect {
        path: String,
        source: std::io::Error,
    },

    #[snafu(display("relay I/O failed"))]
    Relay { source: std::io::Error },

    #[snafu(display("relay task panicked"))]
    RelayJoin { source: tokio::task::JoinError },
}

/// Send `ChannelOpenFailure` with `SSH_OPEN_CONNECT_FAILED`.
async fn send_open_failure<R, W: AsyncWrite + Unpin + Send>(
    pending: PendingChannel<R, W>,
    description: &str,
) -> Result<(), DirectForwardError> {
    pending
        .reject(reason_code::CONNECT_FAILED, description.to_owned().into())
        .await
        .context(direct_forward_error::RejectSnafu)
}

/// Send `ChannelOpenConfirmation` and return the raw stream pair.
async fn send_open_confirmation<R, W: AsyncWrite + Unpin + Send>(
    pending: PendingChannel<R, W>,
) -> Result<(R, W), DirectForwardError> {
    pending
        .accept(crate::constants::DEFAULT_MAX_MESSAGE_SIZE)
        .await
        .context(direct_forward_error::AcceptSnafu)
        .map(|ch| ch.into_parts())
}

/// Spawn bidirectional relay between a channel stream pair and a split I/O stream.
async fn relay_bidirectional<R, W, SR, SW>(
    channel_reader: R,
    channel_writer: W,
    stream_reader: SR,
    stream_writer: SW,
) -> Result<(), DirectForwardError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    SR: AsyncRead + Send + Unpin + 'static,
    SW: AsyncWrite + Send + Unpin + 'static,
{
    let ch2s = tokio::spawn(relay(channel_reader, stream_writer));
    let s2ch = tokio::spawn(relay(stream_reader, channel_writer));
    let (r1, r2) = tokio::join!(ch2s, s2ch);
    r1.context(direct_forward_error::RelayJoinSnafu)?
        .context(direct_forward_error::RelaySnafu)?;
    r2.context(direct_forward_error::RelayJoinSnafu)?
        .context(direct_forward_error::RelaySnafu)?;
    Ok(())
}

/// Handle a `direct-tcpip` channel (RFC 4254 §7.2).
///
/// Reads destination and originator fields, connects to `dest_host:dest_port`,
/// sends confirmation, then relays raw bytes.
///
/// On connect failure, sends `ChannelOpenFailure` and returns `Ok(())`.
pub async fn handle_direct_tcpip<R, W>(mut reader: R, writer: W) -> Result<(), DirectForwardError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let dest_host: SshString = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeSnafu)?;
    let dest_port: VarInt = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeVarintSnafu)?;
    let _originator_host: SshString = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeSnafu)?;
    let _originator_port: VarInt = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeVarintSnafu)?;

    let raw_port = dest_port.into_inner();
    let port =
        u16::try_from(raw_port).map_err(|_| DirectForwardError::PortOverflow { raw_port })?;

    let pending = PendingChannel::from_raw_parts(reader, writer);
    let addr = format!("{}:{}", &*dest_host, port);
    let tcp_stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%addr, error = %snafu::Report::from_error(&e), "direct-tcpip connect failed");
            send_open_failure(pending, "connect failed").await?;
            return Ok(());
        }
    };

    let (channel_reader, channel_writer) = send_open_confirmation(pending).await?;

    let (tcp_reader, tcp_writer) = tcp_stream.into_split();
    relay_bidirectional(channel_reader, channel_writer, tcp_reader, tcp_writer).await
}

/// Handle a `direct-streamlocal@openssh.com` channel.
///
/// Reads socket path and reserved fields, connects to the Unix socket,
/// sends confirmation, then relays raw bytes.
pub async fn handle_direct_streamlocal<R, W>(
    mut reader: R,
    writer: W,
) -> Result<(), DirectForwardError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let socket_path: SshString = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeSnafu)?;
    let _reserved_string: SshString = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeSnafu)?;
    let _reserved_port: VarInt = reader
        .decode_one()
        .await
        .context(direct_forward_error::DecodeVarintSnafu)?;

    let pending = PendingChannel::from_raw_parts(reader, writer);
    let path = socket_path.to_string();
    let unix_stream = match UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%path, error = %snafu::Report::from_error(&e), "direct-streamlocal connect failed");
            send_open_failure(pending, "connect failed").await?;
            return Ok(());
        }
    };

    let (channel_reader, channel_writer) = send_open_confirmation(pending).await?;

    let (unix_reader, unix_writer) = unix_stream.into_split();
    relay_bidirectional(channel_reader, channel_writer, unix_reader, unix_writer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::read_channel_open_response;
    use h3x::codec::{EncodeExt, EncodeInto};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::net::TcpListener;

    async fn encode_tcpip_request(
        dest_host: &str,
        dest_port: u32,
        originator_host: &str,
        originator_port: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        SshString::from(dest_host.to_owned())
            .encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(dest_port)).await.unwrap();
        SshString::from(originator_host.to_owned())
            .encode_into(&mut buf)
            .await
            .unwrap();
        buf.encode_one(VarInt::from(originator_port)).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn direct_tcpip_echo_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = s.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        let req = encode_tcpip_request("127.0.0.1", port as u32, "127.0.0.1", 12345).await;

        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, mut client_rd) = duplex(8192);

        let send = tokio::spawn(async move {
            client_wr.write_all(&req).await.unwrap();
            client_wr.write_all(b"hello").await.unwrap();
            drop(client_wr);
        });

        let handler = tokio::spawn(handle_direct_tcpip(server_rd, server_wr));

        // Read confirmation via read_channel_open_response
        read_channel_open_response(&mut client_rd).await.unwrap();

        // Read echoed data (raw, NOT wrapped in ChannelData)
        let mut echoed = Vec::new();
        client_rd.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello");

        send.await.unwrap();
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn direct_tcpip_connect_refused() {
        // Port 1 is almost certainly not listening
        let req = encode_tcpip_request("127.0.0.1", 1, "127.0.0.1", 11111).await;

        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, mut client_rd) = duplex(8192);

        client_wr.write_all(&req).await.unwrap();
        drop(client_wr);

        handle_direct_tcpip(server_rd, server_wr).await.unwrap();

        // read_channel_open_response should return a Rejected error
        let result = read_channel_open_response(&mut client_rd).await;
        assert!(matches!(
            result,
            Err(crate::conversation::AwaitOpenError::Rejected { .. })
        ));
    }

    #[tokio::test]
    async fn direct_tcpip_port_overflow() {
        let req = encode_tcpip_request("127.0.0.1", 70000, "127.0.0.1", 11111).await;

        let (mut client_wr, server_rd) = duplex(8192);
        let (server_wr, _client_rd) = duplex(8192);

        client_wr.write_all(&req).await.unwrap();
        drop(client_wr);

        // Port overflow causes PortOverflow error (not a failure message)
        let result = handle_direct_tcpip(server_rd, server_wr).await;
        assert!(result.is_err());
        assert!(
            format!("{:?}", result.unwrap_err()).contains("PortOverflow"),
            "expected PortOverflow error"
        );
    }
}
