use crate::{
    codec::{ChannelHeader, SshString},
    constants::{CHANNEL_SIGNAL_VALUE, DEFAULT_MAX_MESSAGE_SIZE},
    message::SshMessage,
};
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    stream_id::StreamId,
    varint::VarInt,
};
use tokio::io::{self, AsyncRead, AsyncWrite};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardRequest {
    pub bind_address: SshString,
    pub bind_port: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectTcpipRequest {
    pub dest_host: SshString,
    pub dest_port: VarInt,
    pub originator_host: SshString,
    pub originator_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for DirectTcpipRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.dest_host).await?;
        stream.encode_one(self.dest_port).await?;
        stream.encode_one(self.originator_host).await?;
        stream.encode_one(self.originator_port).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for DirectTcpipRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            dest_host: stream.decode_one().await?,
            dest_port: stream.decode_one().await?,
            originator_host: stream.decode_one().await?,
            originator_port: stream.decode_one().await?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for TcpipForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.bind_address).await?;
        stream.encode_one(self.bind_port).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for TcpipForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            bind_address: stream.decode_one().await?,
            bind_port: stream.decode_one().await?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelTcpipForwardRequest {
    pub bind_address: SshString,
    pub bind_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for CancelTcpipForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.bind_address).await?;
        stream.encode_one(self.bind_port).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for CancelTcpipForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            bind_address: stream.decode_one().await?,
            bind_port: stream.decode_one().await?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardReply {
    pub allocated_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for TcpipForwardReply {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.allocated_port).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for TcpipForwardReply {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            allocated_port: stream.decode_one().await?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedTcpipRequest {
    pub connected_address: SshString,
    pub connected_port: VarInt,
    pub originator_address: SshString,
    pub originator_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ForwardedTcpipRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.connected_address).await?;
        stream.encode_one(self.connected_port).await?;
        stream.encode_one(self.originator_address).await?;
        stream.encode_one(self.originator_port).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ForwardedTcpipRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            connected_address: stream.decode_one().await?,
            connected_port: stream.decode_one().await?,
            originator_address: stream.decode_one().await?,
            originator_port: stream.decode_one().await?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamlocalForwardRequest {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for StreamlocalForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.socket_path).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for StreamlocalForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            socket_path: stream.decode_one().await?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelStreamlocalForwardRequest {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for CancelStreamlocalForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.socket_path).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for CancelStreamlocalForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            socket_path: stream.decode_one().await?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedStreamlocalRequest {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ForwardedStreamlocalRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(self.socket_path).await?;
        stream.encode_one(SshString::from("")).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ForwardedStreamlocalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let socket_path = stream.decode_one().await?;
        let _: SshString = stream.decode_one().await?;
        Ok(Self { socket_path })
    }
}

pub async fn encode_direct_tcpip_request_data(
    dest_host: &str,
    dest_port: u32,
    originator_host: &str,
    originator_port: u32,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.encode_one(DirectTcpipRequest {
        dest_host: dest_host.to_owned().into(),
        dest_port: dest_port.into(),
        originator_host: originator_host.to_owned().into(),
        originator_port: originator_port.into(),
    })
    .await?;
    Ok(buf)
}

pub async fn write_direct_tcpip_channel_open<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    conversation_id: StreamId,
    dest_host: &str,
    dest_port: u32,
    originator_host: &str,
    originator_port: u32,
) -> io::Result<()> {
    let header = ChannelHeader {
        signal_value: CHANNEL_SIGNAL_VALUE,
        conversation_id,
        channel_type: "direct-tcpip".into(),
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    writer.encode_one(header).await?;
    writer
        .encode_one(DirectTcpipRequest {
            dest_host: dest_host.to_owned().into(),
            dest_port: dest_port.into(),
            originator_host: originator_host.to_owned().into(),
            originator_port: originator_port.into(),
        })
        .await?;
    Ok(())
}

pub async fn parse_tcpip_forward_reply(
    mut data: &[u8],
    original_bind_port: u32,
) -> io::Result<u32> {
    if data.is_empty() {
        Ok(original_bind_port)
    } else {
        let reply: TcpipForwardReply = data.decode_one().await?;
        Ok(reply.allocated_port.into_inner() as u32)
    }
}

pub async fn read_forwarded_tcpip_info<R: AsyncRead + Send + Unpin>(
    reader: &mut R,
) -> io::Result<ForwardedTcpipRequest> {
    reader.decode_one().await
}

pub async fn accept_forwarded_channel<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
) -> io::Result<()> {
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    writer.encode_one(&confirm).await
}

pub async fn reject_forwarded_channel<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    reason_code: VarInt,
    description: &str,
) -> io::Result<()> {
    let failure = SshMessage::ChannelOpenFailure {
        reason_code,
        description: description.to_owned(),
    };
    writer.encode_one(&failure).await
}
