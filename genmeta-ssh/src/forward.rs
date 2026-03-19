use crate::{
    CHANNEL_SIGNAL_VALUE, DEFAULT_MAX_MESSAGE_SIZE,
    codec::{ChannelHeader, SshString},
    message::SshMessage,
};
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use tokio::io::{self, AsyncRead, AsyncWrite};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardRequest {
    pub bind_address: String,
    pub bind_port: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectTcpipRequest {
    pub dest_host: String,
    pub dest_port: u32,
    pub originator_host: String,
    pub originator_port: u32,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &DirectTcpipRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.dest_host.clone())).await?;
        stream.encode_one(VarInt::from(self.dest_port)).await?;
        stream.encode_one(SshString(self.originator_host.clone())).await?;
        stream.encode_one(VarInt::from(self.originator_port)).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for DirectTcpipRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let dest_host: SshString = stream.decode_one().await?;
        let dest_port: VarInt = stream.decode_one().await?;
        let originator_host: SshString = stream.decode_one().await?;
        let originator_port: VarInt = stream.decode_one().await?;
        Ok(Self {
            dest_host: dest_host.0,
            dest_port: dest_port.into_inner() as u32,
            originator_host: originator_host.0,
            originator_port: originator_port.into_inner() as u32,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &TcpipForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.bind_address.clone())).await?;
        stream.encode_one(VarInt::from(self.bind_port)).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for TcpipForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let bind_address: SshString = stream.decode_one().await?;
        let bind_port: VarInt = stream.decode_one().await?;
        Ok(Self {
            bind_address: bind_address.0,
            bind_port: bind_port.into_inner() as u32,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelTcpipForwardRequest {
    pub bind_address: String,
    pub bind_port: u32,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &CancelTcpipForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.bind_address.clone())).await?;
        stream.encode_one(VarInt::from(self.bind_port)).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for CancelTcpipForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let bind_address: SshString = stream.decode_one().await?;
        let bind_port: VarInt = stream.decode_one().await?;
        Ok(Self {
            bind_address: bind_address.0,
            bind_port: bind_port.into_inner() as u32,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardReply {
    pub allocated_port: u32,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &TcpipForwardReply {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(VarInt::from(self.allocated_port)).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for TcpipForwardReply {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let allocated_port: VarInt = stream.decode_one().await?;
        Ok(Self {
            allocated_port: allocated_port.into_inner() as u32,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedTcpipRequest {
    pub connected_address: String,
    pub connected_port: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ForwardedTcpipRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.connected_address.clone())).await?;
        stream.encode_one(VarInt::from(self.connected_port)).await?;
        stream.encode_one(SshString(self.originator_address.clone())).await?;
        stream.encode_one(VarInt::from(self.originator_port)).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ForwardedTcpipRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let connected_address: SshString = stream.decode_one().await?;
        let connected_port: VarInt = stream.decode_one().await?;
        let originator_address: SshString = stream.decode_one().await?;
        let originator_port: VarInt = stream.decode_one().await?;
        Ok(Self {
            connected_address: connected_address.0,
            connected_port: connected_port.into_inner() as u32,
            originator_address: originator_address.0,
            originator_port: originator_port.into_inner() as u32,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamlocalForwardRequest {
    pub socket_path: String,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &StreamlocalForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.socket_path.clone())).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for StreamlocalForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let socket_path: SshString = stream.decode_one().await?;
        Ok(Self {
            socket_path: socket_path.0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelStreamlocalForwardRequest {
    pub socket_path: String,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &CancelStreamlocalForwardRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.socket_path.clone())).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for CancelStreamlocalForwardRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let socket_path: SshString = stream.decode_one().await?;
        Ok(Self {
            socket_path: socket_path.0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedStreamlocalRequest {
    pub socket_path: String,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &ForwardedStreamlocalRequest {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream.encode_one(SshString(self.socket_path.clone())).await?;
        stream.encode_one(SshString(String::new())).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ForwardedStreamlocalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let socket_path: SshString = stream.decode_one().await?;
        let _: SshString = stream.decode_one().await?;
        Ok(Self {
            socket_path: socket_path.0,
        })
    }
}

pub async fn encode_direct_tcpip_request_data(
    dest_host: &str,
    dest_port: u32,
    originator_host: &str,
    originator_port: u32,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.encode_one(&DirectTcpipRequest {
        dest_host: dest_host.to_owned(),
        dest_port,
        originator_host: originator_host.to_owned(),
        originator_port,
    })
    .await?;
    Ok(buf)
}

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
    writer.encode_one(&header).await?;
    writer
        .encode_one(&DirectTcpipRequest {
            dest_host: dest_host.to_owned(),
            dest_port,
            originator_host: originator_host.to_owned(),
            originator_port,
        })
        .await?;
    Ok(())
}

pub async fn parse_tcpip_forward_reply(mut data: &[u8], original_bind_port: u32) -> io::Result<u32> {
    if data.is_empty() {
        Ok(original_bind_port)
    } else {
        let reply: TcpipForwardReply = data.decode_one().await?;
        Ok(reply.allocated_port)
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
        max_message_size: VarInt::from(DEFAULT_MAX_MESSAGE_SIZE as u32),
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
