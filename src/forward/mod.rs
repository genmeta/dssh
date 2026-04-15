#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod direct;
#[cfg(feature = "server")]
pub mod reverse;
#[cfg(feature = "server")]
pub mod socks5;
#[cfg(feature = "client")]
pub mod spec;

use crate::codec::{CodecError, SshString};
use crate::conversation::{ChannelOpen, EmptyPayload, WantReplyGlobalRequest};
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

/// Copy all bytes from `reader` to `writer`, then shut down the writer.
pub async fn relay<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(n)
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum ForwardError {
    #[snafu(display("forward codec failed"))]
    Codec { source: CodecError },

    #[snafu(display("forward stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("forward stream write failed"))]
    WriteIo { source: std::io::Error },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardRequest {
    pub bind_address: SshString,
    pub bind_port: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectTcpip {
    pub dest_host: SshString,
    pub dest_port: VarInt,
    pub originator_host: SshString,
    pub originator_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for DirectTcpip {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.dest_host)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(self.dest_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        stream
            .encode_one(self.originator_host)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(self.originator_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for DirectTcpip {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            dest_host: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
            dest_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
            originator_host: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
            originator_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for TcpipForwardRequest {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.bind_address)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(self.bind_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for TcpipForwardRequest {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            bind_address: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
            bind_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
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
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.bind_address)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(self.bind_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for CancelTcpipForwardRequest {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            bind_address: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
            bind_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipForwardReply {
    pub allocated_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for TcpipForwardReply {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.allocated_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for TcpipForwardReply {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            allocated_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForwardedTcpip {
    pub connected_address: SshString,
    pub connected_port: VarInt,
    pub originator_address: SshString,
    pub originator_port: VarInt,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ForwardedTcpip {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.connected_address)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(self.connected_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        stream
            .encode_one(self.originator_address)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(self.originator_port)
            .await
            .context(forward_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ForwardedTcpip {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            connected_address: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
            connected_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
            originator_address: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
            originator_port: stream
                .decode_one()
                .await
                .context(forward_error::ReadIoSnafu)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamlocalForwardRequest {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for StreamlocalForwardRequest {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.socket_path)
            .await
            .context(forward_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for StreamlocalForwardRequest {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            socket_path: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelStreamlocalForwardRequest {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for CancelStreamlocalForwardRequest {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.socket_path)
            .await
            .context(forward_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for CancelStreamlocalForwardRequest {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        Ok(Self {
            socket_path: stream
                .decode_one()
                .await
                .context(forward_error::CodecSnafu)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForwardedStreamlocal {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ForwardedStreamlocal {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.socket_path)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(SshString::from(""))
            .await
            .context(forward_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ForwardedStreamlocal {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let socket_path = stream
            .decode_one()
            .await
            .context(forward_error::CodecSnafu)?;
        let _: SshString = stream
            .decode_one()
            .await
            .context(forward_error::CodecSnafu)?;
        Ok(Self { socket_path })
    }
}

// ===========================================================================
// DirectStreamlocal — channel open payload for direct-streamlocal
// ===========================================================================

/// Channel open payload for `"direct-streamlocal@openssh.com"`.
///
/// Wire format: `socket_path(SshString) + reserved(SshString, empty) + reserved(VarInt, 0)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectStreamlocal {
    pub socket_path: SshString,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for DirectStreamlocal {
    type Output = ();
    type Error = ForwardError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = std::pin::pin!(stream);
        stream
            .encode_one(self.socket_path)
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(SshString::from_static(""))
            .await
            .context(forward_error::CodecSnafu)?;
        stream
            .encode_one(VarInt::from_u32(0))
            .await
            .context(forward_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for DirectStreamlocal {
    type Error = ForwardError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = std::pin::pin!(stream);
        let socket_path = stream
            .decode_one()
            .await
            .context(forward_error::CodecSnafu)?;
        let _: SshString = stream
            .decode_one()
            .await
            .context(forward_error::CodecSnafu)?;
        let _: VarInt = stream
            .decode_one()
            .await
            .context(forward_error::ReadIoSnafu)?;
        Ok(Self { socket_path })
    }
}

// ===========================================================================
// ChannelOpen implementations
// ===========================================================================

/// Channel open for `"session"` — no extra payload.
#[derive(Debug, Clone)]
pub struct SessionChannelOpen;

impl ChannelOpen for SessionChannelOpen {
    fn channel_type(&self) -> SshString {
        SshString::from_static("session")
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for SessionChannelOpen {
    type Output = ();
    type Error = std::convert::Infallible;

    async fn encode_into(self, _stream: S) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ChannelOpen for DirectTcpip {
    fn channel_type(&self) -> SshString {
        SshString::from_static("direct-tcpip")
    }
}

impl ChannelOpen for ForwardedTcpip {
    fn channel_type(&self) -> SshString {
        SshString::from_static("forwarded-tcpip")
    }
}

impl ChannelOpen for DirectStreamlocal {
    fn channel_type(&self) -> SshString {
        SshString::from_static("direct-streamlocal@openssh.com")
    }
}

impl ChannelOpen for ForwardedStreamlocal {
    fn channel_type(&self) -> SshString {
        SshString::from_static("forwarded-streamlocal@openssh.com")
    }
}

/// Channel open for `"socks5"` — no extra payload.
#[derive(Debug, Clone)]
pub struct Socks5ChannelOpen;

impl ChannelOpen for Socks5ChannelOpen {
    fn channel_type(&self) -> SshString {
        SshString::from_static("socks5")
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for Socks5ChannelOpen {
    type Output = ();
    type Error = std::convert::Infallible;

    async fn encode_into(self, _stream: S) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ===========================================================================
// WantReplyGlobalRequest implementations for forwarding
// ===========================================================================

/// Global request `"tcpip-forward"` — asks the server to listen on a port.
///
/// Success response contains the allocated port.
#[derive(Debug, Clone)]
pub struct TcpipForwardGlobalRequest {
    pub payload: TcpipForwardRequest,
}

impl WantReplyGlobalRequest for TcpipForwardGlobalRequest {
    type Success = TcpipForwardReply;
    type Payload = TcpipForwardRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("tcpip-forward")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Global request `"cancel-tcpip-forward"` — stops listening on a port.
///
/// Success response carries no data.
#[derive(Debug, Clone)]
pub struct CancelTcpipForwardGlobalRequest {
    pub payload: CancelTcpipForwardRequest,
}

impl WantReplyGlobalRequest for CancelTcpipForwardGlobalRequest {
    type Success = EmptyPayload;
    type Payload = CancelTcpipForwardRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("cancel-tcpip-forward")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Global request `"streamlocal-forward@openssh.com"` — asks the server
/// to listen on a Unix domain socket.
#[derive(Debug, Clone)]
pub struct StreamlocalForwardGlobalRequest {
    pub payload: StreamlocalForwardRequest,
}

impl WantReplyGlobalRequest for StreamlocalForwardGlobalRequest {
    type Success = EmptyPayload;
    type Payload = StreamlocalForwardRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("streamlocal-forward@openssh.com")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Global request `"cancel-streamlocal-forward@openssh.com"` — stops
/// listening on a Unix domain socket.
#[derive(Debug, Clone)]
pub struct CancelStreamlocalForwardGlobalRequest {
    pub payload: CancelStreamlocalForwardRequest,
}

impl WantReplyGlobalRequest for CancelStreamlocalForwardGlobalRequest {
    type Success = EmptyPayload;
    type Payload = CancelStreamlocalForwardRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("cancel-streamlocal-forward@openssh.com")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}
