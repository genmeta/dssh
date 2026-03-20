use crate::{
    codec::ChannelHeader,
    constants::{CHANNEL_SIGNAL_VALUE, DEFAULT_MAX_MESSAGE_SIZE},
    forward::{ForwardedStreamlocalRequest, ForwardedTcpipRequest},
    message::SshMessage,
};
use h3x::{
    codec::{DecodeExt, EncodeExt},
    stream_id::StreamId,
};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

pub async fn relay<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(n)
}

pub fn forwarded_tcpip_header(conversation_id: StreamId) -> ChannelHeader {
    ChannelHeader {
        signal_value: CHANNEL_SIGNAL_VALUE,
        conversation_id,
        channel_type: "forwarded-tcpip".into(),
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    }
}

pub async fn finish_forwarded_tcpip_channel<R, W, S>(
    mut reader: R,
    mut writer: W,
    tcp_stream: S,
    connected_addr: &str,
    connected_port: u16,
    originator_addr: &str,
    originator_port: u16,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    writer
        .encode_one(ForwardedTcpipRequest {
            connected_address: connected_addr.to_string().into(),
            connected_port: connected_port.into(),
            originator_address: originator_addr.to_string().into(),
            originator_port: originator_port.into(),
        })
        .await?;
    writer.flush().await?;

    let response: SshMessage = reader.decode_one().await?;
    match response {
        SshMessage::ChannelOpenConfirmation { .. } => {}
        SshMessage::ChannelOpenFailure { .. } => return Ok(()),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected ChannelOpenConfirmation or ChannelOpenFailure, got {other:?}"),
            ));
        }
    }

    let (stream_reader, stream_writer) = tokio::io::split(tcp_stream);
    let q2t = tokio::spawn(relay(reader, stream_writer));
    let t2q = tokio::spawn(relay(stream_reader, writer));
    let _ = tokio::join!(q2t, t2q);
    Ok(())
}

pub fn forwarded_streamlocal_header(conversation_id: StreamId) -> ChannelHeader {
    ChannelHeader {
        signal_value: CHANNEL_SIGNAL_VALUE,
        conversation_id,
        channel_type: "forwarded-streamlocal@openssh.com".into(),
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    }
}

pub async fn finish_forwarded_streamlocal_channel<R, W, S>(
    mut reader: R,
    mut writer: W,
    unix_stream: S,
    socket_path: &str,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    writer
        .encode_one(ForwardedStreamlocalRequest {
            socket_path: socket_path.to_string().into(),
        })
        .await?;
    writer.flush().await?;

    let response: SshMessage = reader.decode_one().await?;
    match response {
        SshMessage::ChannelOpenConfirmation { .. } => {}
        SshMessage::ChannelOpenFailure { .. } => return Ok(()),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected ChannelOpenConfirmation or ChannelOpenFailure, got {other:?}"),
            ));
        }
    }

    let (stream_reader, stream_writer) = tokio::io::split(unix_stream);
    let q2u = tokio::spawn(relay(reader, stream_writer));
    let u2q = tokio::spawn(relay(stream_reader, writer));
    let _ = tokio::join!(q2u, u2q);
    Ok(())
}
