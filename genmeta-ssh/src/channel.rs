use std::pin::pin;

use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    stream_id::StreamId,
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    codec::{CodecError, RawRemainder, SshBool, SshBytes, SshString},
    constants::CHANNEL_SIGNAL_VALUE,
    forward::{
        DirectTcpipRequest, ForwardError, ForwardedStreamlocalRequest, ForwardedTcpipRequest,
        TcpipForwardReply,
    },
    session::{
        ExecRequest, ExitSignalRequest, ExitStatusRequest, PtyRequest, SessionCodecError,
        SignalRequest,
        SubsystemRequest, WindowChangeRequest,
    },
};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum ChannelError {
    #[snafu(display("channel codec failed"))]
    Codec { source: CodecError },

    #[snafu(display("channel forward codec failed"))]
    Forward { source: ForwardError },

    #[snafu(display("channel session codec failed"))]
    SessionCodec { source: SessionCodecError },

    #[snafu(display("channel stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("channel stream write failed"))]
    WriteIo { source: std::io::Error },

    #[snafu(display("unexpected channel signal value {signal_value}"))]
    UnexpectedSignalValue { signal_value: VarInt },

    #[snafu(display("unknown body is unavailable for encoding for {kind}"))]
    UnknownBodyUnavailable { kind: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChannelType {
    Session,
    DirectTcpip,
    ForwardedTcpip,
    DirectStreamlocal,
    ForwardedStreamlocal,
    Socks5,
    Unknown,
}

impl ChannelType {
    pub fn as_ssh_name(self) -> SshString {
        match self {
            Self::Session => SshString::from_static("session"),
            Self::DirectTcpip => SshString::from_static("direct-tcpip"),
            Self::ForwardedTcpip => SshString::from_static("forwarded-tcpip"),
            Self::DirectStreamlocal => SshString::from_static("direct-streamlocal@openssh.com"),
            Self::ForwardedStreamlocal => {
                SshString::from_static("forwarded-streamlocal@openssh.com")
            }
            Self::Socks5 => SshString::from_static("socks5"),
            Self::Unknown => SshString::from_static("unknown"),
        }
    }

    pub fn from_ssh_name(name: &str) -> Self {
        match name {
            "session" => Self::Session,
            "direct-tcpip" => Self::DirectTcpip,
            "forwarded-tcpip" => Self::ForwardedTcpip,
            "direct-streamlocal@openssh.com" => Self::DirectStreamlocal,
            "forwarded-streamlocal@openssh.com" => Self::ForwardedStreamlocal,
            "socks5" => Self::Socks5,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelHeader {
    pub session_id: StreamId,
    pub max_message_size: VarInt,
    pub body: ChannelOpenBody,
}

impl ChannelHeader {
    pub fn signal_value(&self) -> VarInt {
        CHANNEL_SIGNAL_VALUE
    }

    pub fn channel_type(&self) -> ChannelType {
        self.body.channel_type()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChannelOpenBody {
    Session,
    DirectTcpip(DirectTcpipRequest),
    ForwardedTcpip(ForwardedTcpipRequest),
    DirectStreamlocal { socket_path: SshString },
    ForwardedStreamlocal(ForwardedStreamlocalRequest),
    Socks5,
    Unknown { channel_type: SshString },
}

impl ChannelOpenBody {
    pub fn channel_type(&self) -> ChannelType {
        match self {
            Self::Session => ChannelType::Session,
            Self::DirectTcpip(_) => ChannelType::DirectTcpip,
            Self::ForwardedTcpip(_) => ChannelType::ForwardedTcpip,
            Self::DirectStreamlocal { .. } => ChannelType::DirectStreamlocal,
            Self::ForwardedStreamlocal(_) => ChannelType::ForwardedStreamlocal,
            Self::Socks5 => ChannelType::Socks5,
            Self::Unknown { .. } => ChannelType::Unknown,
        }
    }

    pub fn channel_name(&self) -> SshString {
        match self {
            Self::Unknown { channel_type } => channel_type.clone(),
            _ => self.channel_type().as_ssh_name(),
        }
    }

    async fn encode_extra<S: AsyncWrite + Send>(&self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        match self {
            Self::Session | Self::Socks5 | Self::Unknown { .. } => Ok(()),
            Self::DirectTcpip(req) => {
                stream.encode_one(req.clone()).await.context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::ForwardedTcpip(req) => {
                stream.encode_one(req.clone()).await.context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::DirectStreamlocal { socket_path } => {
                stream.encode_one(socket_path.clone()).await.context(channel_error::CodecSnafu)?;
                stream
                    .encode_one(SshString::from_static(""))
                    .await
                    .context(channel_error::CodecSnafu)?;
                stream
                    .encode_one(VarInt::from_u32(0))
                    .await
                    .context(channel_error::WriteIoSnafu)?;
                Ok(())
            }
            Self::ForwardedStreamlocal(req) => {
                stream.encode_one(req.clone()).await.context(channel_error::ForwardSnafu)?;
                Ok(())
            }
        }
    }

    async fn decode_extra<S: AsyncRead + Send>(
        channel_type: SshString,
        stream: S,
    ) -> Result<Self, ChannelError> {
        let mut stream = pin!(stream);
        Ok(match ChannelType::from_ssh_name(&channel_type) {
            ChannelType::Session => Self::Session,
            ChannelType::DirectTcpip => {
                Self::DirectTcpip(stream.decode_one().await.context(channel_error::ForwardSnafu)?)
            }
            ChannelType::ForwardedTcpip => {
                Self::ForwardedTcpip(stream.decode_one().await.context(channel_error::ForwardSnafu)?)
            }
            ChannelType::DirectStreamlocal => {
                let socket_path: SshString = stream.decode_one().await.context(channel_error::CodecSnafu)?;
                let _: SshString = stream.decode_one().await.context(channel_error::CodecSnafu)?;
                let _: VarInt = stream.decode_one().await.context(channel_error::ReadIoSnafu)?;
                Self::DirectStreamlocal { socket_path }
            }
            ChannelType::ForwardedStreamlocal => {
                Self::ForwardedStreamlocal(stream.decode_one().await.context(channel_error::ForwardSnafu)?)
            }
            ChannelType::Socks5 => Self::Socks5,
            ChannelType::Unknown => Self::Unknown { channel_type },
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ChannelOpenBody {
    type Output = ();
    type Error = ChannelError;

    async fn encode_into(self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        stream.encode_one(self.channel_name()).await.context(channel_error::CodecSnafu)?;
        self.encode_extra(&mut stream).await
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ChannelOpenBody {
    type Error = ChannelError;

    async fn decode_from(stream: S) -> Result<Self, ChannelError> {
        let mut stream = pin!(stream);
        let channel_type: SshString = stream.decode_one().await.context(channel_error::CodecSnafu)?;
        Self::decode_extra(channel_type, &mut stream).await
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ChannelHeader {
    type Output = ();
    type Error = ChannelError;

    async fn encode_into(self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        stream
            .encode_one(CHANNEL_SIGNAL_VALUE)
            .await
            .context(channel_error::WriteIoSnafu)?;
        stream
            .encode_one(self.session_id)
            .await
            .context(channel_error::WriteIoSnafu)?;
        stream
            .encode_one(self.max_message_size)
            .await
            .context(channel_error::WriteIoSnafu)?;
        stream.encode_one(self.body).await
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ChannelHeader {
    type Error = ChannelError;

    async fn decode_from(stream: S) -> Result<Self, ChannelError> {
        let mut stream = pin!(stream);
        let signal_value: VarInt = stream.decode_one().await.context(channel_error::ReadIoSnafu)?;
        if signal_value != CHANNEL_SIGNAL_VALUE {
            return Err(ChannelError::UnexpectedSignalValue {
                signal_value,
            });
        }

        let session_id = stream.decode_one().await.context(channel_error::ReadIoSnafu)?;
        let max_message_size = stream.decode_one().await.context(channel_error::ReadIoSnafu)?;
        let body = stream.decode_one().await?;
        Ok(Self {
            session_id,
            max_message_size,
            body,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownBody {
    Unavailable,
    Raw(RawRemainder),
}

impl UnknownBody {
    fn into_raw(self, kind: &'static str) -> Result<RawRemainder, ChannelError> {
        match self {
            Self::Raw(raw) => Ok(raw),
            Self::Unavailable => Err(ChannelError::UnknownBodyUnavailable { kind }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRequest {
    PtyReq {
        want_reply: SshBool,
        request: PtyRequest,
    },
    Exec {
        want_reply: SshBool,
        request: ExecRequest,
    },
    Shell {
        want_reply: SshBool,
    },
    Subsystem {
        want_reply: SshBool,
        request: SubsystemRequest,
    },
    WindowChange(WindowChangeRequest),
    Signal {
        want_reply: SshBool,
        request: SignalRequest,
    },
    ExitStatus(ExitStatusRequest),
    ExitSignal(ExitSignalRequest),
    Unknown {
        request_type: SshString,
        want_reply: SshBool,
        body: UnknownBody,
    },
}

impl ChannelRequest {
    pub fn request_type(&self) -> SshString {
        match self {
            Self::PtyReq { .. } => SshString::from_static("pty-req"),
            Self::Exec { .. } => SshString::from_static("exec"),
            Self::Shell { .. } => SshString::from_static("shell"),
            Self::Subsystem { .. } => SshString::from_static("subsystem"),
            Self::WindowChange(_) => SshString::from_static("window-change"),
            Self::Signal { .. } => SshString::from_static("signal"),
            Self::ExitStatus(_) => SshString::from_static("exit-status"),
            Self::ExitSignal(_) => SshString::from_static("exit-signal"),
            Self::Unknown { request_type, .. } => request_type.clone(),
        }
    }

    pub fn want_reply(&self) -> SshBool {
        match self {
            Self::PtyReq { want_reply, .. }
            | Self::Exec { want_reply, .. }
            | Self::Shell { want_reply }
            | Self::Subsystem { want_reply, .. }
            | Self::Signal { want_reply, .. }
            | Self::Unknown { want_reply, .. } => want_reply.clone(),
            Self::WindowChange(_) | Self::ExitStatus(_) | Self::ExitSignal(_) => SshBool(false),
        }
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ChannelRequest {
    type Output = ();
    type Error = ChannelError;

    async fn encode_into(self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        stream.encode_one(self.request_type()).await.context(channel_error::CodecSnafu)?;
        stream.encode_one(self.want_reply()).await.context(channel_error::CodecSnafu)?;
        match self {
            Self::PtyReq { request, .. } => {
                stream.encode_one(request).await.context(channel_error::SessionCodecSnafu)?;
                Ok(())
            }
            Self::Exec { request, .. } => {
                stream.encode_one(request).await.context(channel_error::SessionCodecSnafu)?;
                Ok(())
            }
            Self::Shell { .. } => Ok(()),
            Self::Subsystem { request, .. } => {
                stream
                    .encode_one(SshString::from(request.subsystem_name.clone()))
                    .await
                    .context(channel_error::CodecSnafu)?;
                Ok(())
            }
            Self::WindowChange(request) => {
                stream.encode_one(request).await.context(channel_error::SessionCodecSnafu)?;
                Ok(())
            }
            Self::Signal { request, .. } => {
                stream.encode_one(request).await.context(channel_error::SessionCodecSnafu)?;
                Ok(())
            }
            Self::ExitStatus(request) => {
                stream.encode_one(request).await.context(channel_error::SessionCodecSnafu)?;
                Ok(())
            }
            Self::ExitSignal(request) => {
                stream.encode_one(request).await.context(channel_error::SessionCodecSnafu)?;
                Ok(())
            }
            Self::Unknown { body, .. } => {
                let data = body.into_raw("unknown channel request")?;
                stream
                    .write_all(data.as_ref().as_ref())
                    .await
                    .context(channel_error::WriteIoSnafu)?;
                Ok(())
            }
        }
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ChannelRequest {
    type Error = ChannelError;

    async fn decode_from(stream: S) -> Result<Self, ChannelError> {
        let mut stream = pin!(stream);
        let request_type: SshString = stream.decode_one().await.context(channel_error::CodecSnafu)?;
        let want_reply: SshBool = stream.decode_one().await.context(channel_error::CodecSnafu)?;
        Ok(match &*request_type {
            "pty-req" => Self::PtyReq {
                want_reply,
                request: stream.decode_one().await.context(channel_error::SessionCodecSnafu)?,
            },
            "exec" => Self::Exec {
                want_reply,
                request: stream.decode_one().await.context(channel_error::SessionCodecSnafu)?,
            },
            "shell" => Self::Shell { want_reply },
            "subsystem" => Self::Subsystem {
                want_reply,
                request: stream.decode_one().await.context(channel_error::SessionCodecSnafu)?,
            },
            "window-change" => {
                Self::WindowChange(stream.decode_one().await.context(channel_error::SessionCodecSnafu)?)
            }
            "signal" => Self::Signal {
                want_reply,
                request: stream.decode_one().await.context(channel_error::SessionCodecSnafu)?,
            },
            "exit-status" => {
                Self::ExitStatus(stream.decode_one().await.context(channel_error::SessionCodecSnafu)?)
            }
            "exit-signal" => {
                Self::ExitSignal(stream.decode_one().await.context(channel_error::SessionCodecSnafu)?)
            }
            _ => Self::Unknown {
                request_type,
                want_reply,
                body: UnknownBody::Unavailable,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRequestPayload {
    TcpipForward(crate::forward::TcpipForwardRequest),
    CancelTcpipForward(crate::forward::CancelTcpipForwardRequest),
    StreamlocalForward(crate::forward::StreamlocalForwardRequest),
    CancelStreamlocalForward(crate::forward::CancelStreamlocalForwardRequest),
    Unknown {
        request_type: SshString,
        body: UnknownBody,
    },
}

impl GlobalRequestPayload {
    pub fn request_type(&self) -> SshString {
        match self {
            Self::TcpipForward(_) => SshString::from_static("tcpip-forward"),
            Self::CancelTcpipForward(_) => SshString::from_static("cancel-tcpip-forward"),
            Self::StreamlocalForward(_) => {
                SshString::from_static("streamlocal-forward@openssh.com")
            }
            Self::CancelStreamlocalForward(_) => {
                SshString::from_static("cancel-streamlocal-forward@openssh.com")
            }
            Self::Unknown { request_type, .. } => request_type.clone(),
        }
    }

    async fn encode_payload<S: AsyncWrite + Send>(&self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        match self {
            Self::TcpipForward(request) => {
                stream
                    .encode_one(request.clone())
                    .await
                    .context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::CancelTcpipForward(request) => {
                stream
                    .encode_one(request.clone())
                    .await
                    .context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::StreamlocalForward(request) => {
                stream
                    .encode_one(request.clone())
                    .await
                    .context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::CancelStreamlocalForward(request) => {
                stream
                    .encode_one(request.clone())
                    .await
                    .context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::Unknown { body, .. } => {
                let data = body.clone().into_raw("unknown global request")?;
                stream
                    .write_all(data.as_ref().as_ref())
                    .await
                    .context(channel_error::WriteIoSnafu)?;
                Ok(())
            }
        }
    }

    async fn decode_payload<S: AsyncRead + Send>(
        request_type: SshString,
        stream: S,
    ) -> Result<Self, ChannelError> {
        let mut stream = pin!(stream);
        Ok(match &*request_type {
            "tcpip-forward" => {
                Self::TcpipForward(stream.decode_one().await.context(channel_error::ForwardSnafu)?)
            }
            "cancel-tcpip-forward" => Self::CancelTcpipForward(
                stream.decode_one().await.context(channel_error::ForwardSnafu)?,
            ),
            "streamlocal-forward@openssh.com" => Self::StreamlocalForward(
                stream.decode_one().await.context(channel_error::ForwardSnafu)?,
            ),
            "cancel-streamlocal-forward@openssh.com" => Self::CancelStreamlocalForward(
                stream.decode_one().await.context(channel_error::ForwardSnafu)?,
            ),
            _ => Self::Unknown {
                request_type,
                body: UnknownBody::Unavailable,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRequest {
    TcpipForward {
        want_reply: SshBool,
        request: crate::forward::TcpipForwardRequest,
    },
    CancelTcpipForward {
        want_reply: SshBool,
        request: crate::forward::CancelTcpipForwardRequest,
    },
    StreamlocalForward {
        want_reply: SshBool,
        request: crate::forward::StreamlocalForwardRequest,
    },
    CancelStreamlocalForward {
        want_reply: SshBool,
        request: crate::forward::CancelStreamlocalForwardRequest,
    },
    Unknown {
        request_type: SshString,
        want_reply: SshBool,
        body: UnknownBody,
    },
}

impl GlobalRequest {
    pub fn from_payload(payload: GlobalRequestPayload, want_reply: SshBool) -> Self {
        match payload {
            GlobalRequestPayload::TcpipForward(request) => Self::TcpipForward {
                want_reply,
                request,
            },
            GlobalRequestPayload::CancelTcpipForward(request) => Self::CancelTcpipForward {
                want_reply,
                request,
            },
            GlobalRequestPayload::StreamlocalForward(request) => Self::StreamlocalForward {
                want_reply,
                request,
            },
            GlobalRequestPayload::CancelStreamlocalForward(request) => {
                Self::CancelStreamlocalForward {
                    want_reply,
                    request,
                }
            }
            GlobalRequestPayload::Unknown { request_type, body } => Self::Unknown {
                request_type,
                want_reply,
                body,
            },
        }
    }

    pub fn payload(&self) -> GlobalRequestPayload {
        match self {
            Self::TcpipForward { request, .. } => GlobalRequestPayload::TcpipForward(request.clone()),
            Self::CancelTcpipForward { request, .. } => {
                GlobalRequestPayload::CancelTcpipForward(request.clone())
            }
            Self::StreamlocalForward { request, .. } => {
                GlobalRequestPayload::StreamlocalForward(request.clone())
            }
            Self::CancelStreamlocalForward { request, .. } => {
                GlobalRequestPayload::CancelStreamlocalForward(request.clone())
            }
            Self::Unknown {
                request_type,
                body,
                ..
            } => GlobalRequestPayload::Unknown {
                request_type: request_type.clone(),
                body: body.clone(),
            },
        }
    }

    pub fn request_type(&self) -> SshString {
        self.payload().request_type()
    }

    pub fn want_reply(&self) -> SshBool {
        match self {
            Self::TcpipForward { want_reply, .. }
            | Self::CancelTcpipForward { want_reply, .. }
            | Self::StreamlocalForward { want_reply, .. }
            | Self::CancelStreamlocalForward { want_reply, .. }
            | Self::Unknown { want_reply, .. } => want_reply.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalRequestRequest {
    request: GlobalRequestPayload,
}

impl GlobalRequestRequest {
    pub fn new(request: GlobalRequestPayload) -> Self {
        Self { request }
    }

    pub fn request(&self) -> &GlobalRequestPayload {
        &self.request
    }

    pub fn into_request(self) -> GlobalRequestPayload {
        self.request
    }

    pub fn into_wire(self) -> GlobalRequest {
        GlobalRequest::from_payload(self.request, SshBool(true))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalRequestNotice {
    request: GlobalRequestPayload,
}

impl GlobalRequestNotice {
    pub fn new(request: GlobalRequestPayload) -> Self {
        Self { request }
    }

    pub fn request(&self) -> &GlobalRequestPayload {
        &self.request
    }

    pub fn into_request(self) -> GlobalRequestPayload {
        self.request
    }

    pub fn into_wire(self) -> GlobalRequest {
        GlobalRequest::from_payload(self.request, SshBool(false))
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for GlobalRequest {
    type Output = ();
    type Error = ChannelError;

    async fn encode_into(self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.request_type())
            .await
            .context(channel_error::CodecSnafu)?;
        stream
            .encode_one(self.want_reply())
            .await
            .context(channel_error::CodecSnafu)?;
        self.payload().encode_payload(&mut stream).await
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for GlobalRequest {
    type Error = ChannelError;

    async fn decode_from(stream: S) -> Result<Self, ChannelError> {
        let mut stream = pin!(stream);
        let request_type: SshString = stream.decode_one().await.context(channel_error::CodecSnafu)?;
        let want_reply: SshBool = stream.decode_one().await.context(channel_error::CodecSnafu)?;
        let request = GlobalRequestPayload::decode_payload(request_type, &mut stream).await?;
        Ok(Self::from_payload(request, want_reply))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestSuccess {
    Empty,
    TcpipForward(TcpipForwardReply),
    Unknown(UnknownBody),
}

impl<S: AsyncWrite + Send> EncodeInto<S> for RequestSuccess {
    type Output = ();
    type Error = ChannelError;

    async fn encode_into(self, stream: S) -> Result<(), ChannelError> {
        let mut stream = pin!(stream);
        match self {
            Self::Empty => Ok(()),
            Self::TcpipForward(reply) => {
                stream.encode_one(reply).await.context(channel_error::ForwardSnafu)?;
                Ok(())
            }
            Self::Unknown(data) => {
                let data = data.into_raw("unknown request success")?;
                stream
                    .write_all(data.as_ref().as_ref())
                    .await
                    .context(channel_error::WriteIoSnafu)?;
                Ok(())
            }
        }
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for RequestSuccess {
    type Error = ChannelError;

    async fn decode_from(stream: S) -> Result<Self, ChannelError> {
        let _ = stream;
        Ok(Self::Unknown(UnknownBody::Unavailable))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenFailure {
    pub reason_code: VarInt,
    pub description: SshString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelMessage {
    OpenConfirmation { max_message_size: VarInt },
    OpenFailure(ChannelOpenFailure),
    Data(SshBytes),
    ExtendedData { data_type: VarInt, data: SshBytes },
    Request(ChannelRequest),
    Success,
    Failure,
    Eof,
    Close,
}
