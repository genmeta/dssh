use std::pin::pin;

use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    channel::{
        ChannelError, ChannelMessage, ChannelOpenFailure, ChannelRequest,
        UnknownBody,
    },
    codec::{CodecError, SshString},
    session::SessionCodecError,
};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum MessageError {
    #[snafu(display("message codec failed"))]
    Codec { source: CodecError },

    #[snafu(display("message session codec failed"))]
    SessionCodec { source: SessionCodecError },

    #[snafu(display("message stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("message stream write failed"))]
    WriteIo { source: std::io::Error },

    #[snafu(display("channel message codec failed"))]
    Channel { source: ChannelError },

    #[snafu(display("unknown ssh message type {message_type}"))]
    UnknownMessageType { message_type: VarInt },
}

const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: VarInt = VarInt::from_u32(91);
const SSH_MSG_CHANNEL_OPEN_FAILURE: VarInt = VarInt::from_u32(92);
const SSH_MSG_CHANNEL_DATA: VarInt = VarInt::from_u32(94);
const SSH_MSG_CHANNEL_EXTENDED_DATA: VarInt = VarInt::from_u32(95);
const SSH_MSG_CHANNEL_EOF: VarInt = VarInt::from_u32(96);
const SSH_MSG_CHANNEL_CLOSE: VarInt = VarInt::from_u32(97);
const SSH_MSG_CHANNEL_REQUEST: VarInt = VarInt::from_u32(98);
const SSH_MSG_CHANNEL_SUCCESS: VarInt = VarInt::from_u32(99);
const SSH_MSG_CHANNEL_FAILURE: VarInt = VarInt::from_u32(100);

/// SSH channel message, decoded from a per-channel QUIC stream.
///
/// Global requests are no longer part of this enum — they are handled
/// directly by [`Conversation`](crate::conversation::Conversation) using
/// trait-based encoding/decoding on the control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshMessage {
    Channel(ChannelMessage),
}

impl SshMessage {
    pub fn message_type(&self) -> VarInt {
        match self {
            SshMessage::Channel(channel) => match channel {
                ChannelMessage::OpenConfirmation { .. } => SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                ChannelMessage::OpenFailure(_) => SSH_MSG_CHANNEL_OPEN_FAILURE,
                ChannelMessage::Data(_) => SSH_MSG_CHANNEL_DATA,
                ChannelMessage::ExtendedData { .. } => SSH_MSG_CHANNEL_EXTENDED_DATA,
                ChannelMessage::Eof => SSH_MSG_CHANNEL_EOF,
                ChannelMessage::Close => SSH_MSG_CHANNEL_CLOSE,
                ChannelMessage::Request(_) => SSH_MSG_CHANNEL_REQUEST,
                ChannelMessage::Success => SSH_MSG_CHANNEL_SUCCESS,
                ChannelMessage::Failure => SSH_MSG_CHANNEL_FAILURE,
            },
        }
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for SshMessage {
    type Output = ();
    type Error = MessageError;

    async fn encode_into(self, stream: S) -> Result<(), MessageError> {
        let mut stream = pin!(stream);
        match self {
            SshMessage::Channel(message) => match message {
                ChannelMessage::OpenConfirmation { max_message_size } => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream
                        .encode_one(max_message_size)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                }
                ChannelMessage::OpenFailure(failure) => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_OPEN_FAILURE)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream
                        .encode_one(failure.reason_code)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream
                        .encode_one(failure.description)
                        .await
                        .context(message_error::CodecSnafu)?;
                }
                ChannelMessage::Data(data) => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_DATA)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream.encode_one(data).await.context(message_error::CodecSnafu)?;
                }
                ChannelMessage::ExtendedData { data_type, data } => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_EXTENDED_DATA)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream
                        .encode_one(data_type)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream.encode_one(data).await.context(message_error::CodecSnafu)?;
                }
                ChannelMessage::Request(request) => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_REQUEST)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                    stream.encode_one(request).await.context(message_error::ChannelSnafu)?;
                }
                ChannelMessage::Success => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_SUCCESS)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                }
                ChannelMessage::Failure => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_FAILURE)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                }
                ChannelMessage::Eof => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_EOF)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                }
                ChannelMessage::Close => {
                    stream
                        .encode_one(SSH_MSG_CHANNEL_CLOSE)
                        .await
                        .context(message_error::WriteIoSnafu)?;
                }
            },
        }
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshMessage {
    type Error = MessageError;

    async fn decode_from(stream: S) -> Result<Self, MessageError> {
        let mut stream = pin!(stream);
        let msg_type = VarInt::decode_from(&mut stream)
            .await
            .context(message_error::ReadIoSnafu)?;
        match msg_type {
            SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                let max_message_size = stream.decode_one().await.context(message_error::ReadIoSnafu)?;
                Ok(Self::Channel(ChannelMessage::OpenConfirmation { max_message_size }))
            }
            SSH_MSG_CHANNEL_OPEN_FAILURE => {
                let reason_code = stream.decode_one().await.context(message_error::ReadIoSnafu)?;
                let description = stream.decode_one().await.context(message_error::CodecSnafu)?;
                Ok(Self::Channel(ChannelMessage::OpenFailure(
                    ChannelOpenFailure {
                        reason_code,
                        description,
                    },
                )))
            }
            SSH_MSG_CHANNEL_DATA => {
                Ok(Self::Channel(ChannelMessage::Data(
                    stream.decode_one().await.context(message_error::CodecSnafu)?,
                )))
            }
            SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let data_type = stream.decode_one().await.context(message_error::ReadIoSnafu)?;
                Ok(Self::Channel(ChannelMessage::ExtendedData {
                    data_type,
                    data: stream.decode_one().await.context(message_error::CodecSnafu)?,
                }))
            }
            SSH_MSG_CHANNEL_EOF => Ok(Self::Channel(ChannelMessage::Eof)),
            SSH_MSG_CHANNEL_CLOSE => Ok(Self::Channel(ChannelMessage::Close)),
            SSH_MSG_CHANNEL_REQUEST => {
                let request_type: SshString = stream.decode_one().await.context(message_error::CodecSnafu)?;
                let want_reply = stream.decode_one().await.context(message_error::CodecSnafu)?;
                Ok(Self::Channel(ChannelMessage::Request(match &*request_type {
                    "pty-req" => ChannelRequest::PtyReq {
                        want_reply,
                        request: stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    },
                    "exec" => ChannelRequest::Exec {
                        want_reply,
                        request: stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    },
                    "shell" => ChannelRequest::Shell { want_reply },
                    "subsystem" => ChannelRequest::Subsystem {
                        want_reply,
                        request: stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    },
                    "window-change" => ChannelRequest::WindowChange(
                        stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    ),
                    "signal" => ChannelRequest::Signal {
                        want_reply,
                        request: stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    },
                    "exit-status" => ChannelRequest::ExitStatus(
                        stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    ),
                    "exit-signal" => ChannelRequest::ExitSignal(
                        stream.decode_one().await.context(message_error::SessionCodecSnafu)?,
                    ),
                    _ => ChannelRequest::Unknown {
                        request_type,
                        want_reply,
                        body: UnknownBody::Unavailable,
                    },
                })))
            }
            SSH_MSG_CHANNEL_SUCCESS => Ok(Self::Channel(ChannelMessage::Success)),
            SSH_MSG_CHANNEL_FAILURE => Ok(Self::Channel(ChannelMessage::Failure)),
            other => Err(MessageError::UnknownMessageType {
                message_type: other,
            }),
        }
    }
}
