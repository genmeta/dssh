pub mod direct;
pub mod reverse;
pub mod socks5;

use crate::{
    channel::{ChannelHeader, ChannelMessage, ChannelOpenBody},
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    forward::{ForwardedStreamlocalRequest, ForwardedTcpipRequest},
    message::{MessageError, SshMessage},
};
use h3x::{codec::DecodeExt, stream_id::StreamId, varint::VarInt};
use snafu::{ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum ForwardRuntimeError {
    #[snafu(display("forward runtime I/O failed"))]
    Io { source: std::io::Error },

    #[snafu(display("forward relay task failed"))]
    RelayTaskJoin { source: tokio::task::JoinError },

    #[snafu(display("forward runtime message decode failed"))]
    Message { source: MessageError },

    #[snafu(display("unexpected channel open response type {message_type}"))]
    UnexpectedChannelOpenResponse { message_type: VarInt },
}

pub async fn relay<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(n)
}

pub fn forwarded_tcpip_header(
    session_id: StreamId,
    connected_address: &str,
    connected_port: u16,
    originator_address: &str,
    originator_port: u16,
) -> ChannelHeader {
    ChannelHeader {
        session_id,
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        body: ChannelOpenBody::ForwardedTcpip(ForwardedTcpipRequest {
            connected_address: connected_address.to_string().into(),
            connected_port: (connected_port as u32).into(),
            originator_address: originator_address.to_string().into(),
            originator_port: (originator_port as u32).into(),
        }),
    }
}

pub fn forwarded_streamlocal_header(session_id: StreamId, socket_path: &str) -> ChannelHeader {
    ChannelHeader {
        session_id,
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        body: ChannelOpenBody::ForwardedStreamlocal(ForwardedStreamlocalRequest {
            socket_path: socket_path.to_string().into(),
        }),
    }
}

/// Wait for channel open confirmation, then relay bytes bidirectionally
/// between the channel stream and the provided I/O stream.
///
/// Works for any forwarded channel type (TCP, streamlocal, etc.).
pub async fn finish_forwarded_channel<R, W, S>(
    mut reader: R,
    writer: W,
    stream: S,
) -> Result<(), ForwardRuntimeError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let response: SshMessage = reader.decode_one().await.context(forward_runtime_error::MessageSnafu)?;
    match response {
        SshMessage::Channel(ChannelMessage::OpenConfirmation { .. }) => {}
        SshMessage::Channel(ChannelMessage::OpenFailure(..)) => return Ok(()),
        other => {
            return Err(ForwardRuntimeError::UnexpectedChannelOpenResponse {
                message_type: other.message_type(),
            });
        }
    }

    let (stream_reader, stream_writer) = tokio::io::split(stream);
    let ch2s = tokio::spawn(relay(reader, stream_writer));
    let s2ch = tokio::spawn(relay(stream_reader, writer));
    let (r1, r2) = tokio::join!(ch2s, s2ch);
    r1.context(forward_runtime_error::RelayTaskJoinSnafu)?
        .context(forward_runtime_error::IoSnafu)?;
    r2.context(forward_runtime_error::RelayTaskJoinSnafu)?
        .context(forward_runtime_error::IoSnafu)?;
    Ok(())
}

/// Backwards compatibility alias.
pub async fn finish_forwarded_tcpip_channel<R, W, S>(
    reader: R,
    writer: W,
    tcp_stream: S,
) -> Result<(), ForwardRuntimeError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    finish_forwarded_channel(reader, writer, tcp_stream).await
}

/// Backwards compatibility alias.
pub async fn finish_forwarded_streamlocal_channel<R, W, S>(
    reader: R,
    writer: W,
    unix_stream: S,
) -> Result<(), ForwardRuntimeError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    finish_forwarded_channel(reader, writer, unix_stream).await
}
