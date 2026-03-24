use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::channel::ChannelOpenFailure;
use crate::codec::{CodecError, SshBool, SshString};

use super::{
    ManageSessionStream, NotifyChannelRequest, SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA,
    SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_FAILURE,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_REQUEST,
    SSH_MSG_CHANNEL_SUCCESS, WantReplyChannelRequest,
};

// ===========================================================================
// Error types
// ===========================================================================

/// Error from [`super::Conversation::open_channel`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::conversation)))]
pub enum OpenChannelError<ME, PE>
where
    ME: std::error::Error + Send + Sync + 'static,
    PE: std::error::Error + Send + Sync + 'static,
{
    #[snafu(display("failed to open new stream"))]
    OpenStream { source: ME },
    #[snafu(display("failed to encode max message size"))]
    EncodeMaxMessageSize { source: std::io::Error },
    #[snafu(display("failed to encode channel type string"))]
    EncodeChannelType { source: CodecError },
    #[snafu(display("failed to encode channel open payload"))]
    EncodePayload { source: PE },
    #[snafu(display("failed to flush channel stream after open"))]
    Flush { source: std::io::Error },
    #[snafu(display("failed to read channel open confirmation"))]
    AwaitConfirmation { source: AwaitOpenError },
}

/// Error from [`super::Conversation::accept_channel`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::conversation)))]
pub enum AcceptChannelError<ME>
where
    ME: std::error::Error + Send + Sync + 'static,
{
    #[snafu(display("failed to accept incoming stream"))]
    AcceptStream { source: ME },
    #[snafu(display("failed to decode max message size"))]
    DecodeMaxMessageSize { source: std::io::Error },
    #[snafu(display("failed to decode channel type string"))]
    DecodeChannelType { source: CodecError },
}

/// Error from [`SshChannel::request`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SendChannelRequestError<
    PE: std::error::Error + Send + Sync + 'static,
    SE: std::error::Error + Send + Sync + 'static,
> {
    #[snafu(display("failed to encode channel request message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode channel request type string"))]
    EncodeRequestType { source: CodecError },
    #[snafu(display("failed to encode want_reply flag"))]
    EncodeWantReply { source: CodecError },
    #[snafu(display("failed to encode channel request payload"))]
    EncodePayload { source: PE },
    #[snafu(display("failed to flush channel stream after request"))]
    Flush { source: std::io::Error },
    #[snafu(display("failed to decode channel response message type"))]
    DecodeResponseType { source: std::io::Error },
    #[snafu(display("failed to decode channel success response"))]
    DecodeSuccess { source: SE },
    #[snafu(display("channel request was rejected by remote"))]
    Rejected,
    #[snafu(display("unexpected channel response message type {message_type}"))]
    UnexpectedResponseType { message_type: VarInt },
}

/// Error from [`SshChannelWriter::notice`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SendChannelNoticeError<PE: std::error::Error + Send + Sync + 'static> {
    #[snafu(display("failed to encode channel notice message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode channel notice type string"))]
    EncodeRequestType { source: CodecError },
    #[snafu(display("failed to encode want_reply flag"))]
    EncodeWantReply { source: CodecError },
    #[snafu(display("failed to encode channel notice payload"))]
    EncodePayload { source: PE },
    #[snafu(display("failed to flush channel stream after notice"))]
    Flush { source: std::io::Error },
}

/// Error from [`SshChannel::next_event`] and [`SshChannelReader::next_event`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadChannelEventError {
    #[snafu(display("failed to decode channel message type"))]
    DecodeMessageType { source: std::io::Error },
    #[snafu(display("failed to decode channel data length"))]
    DecodeData { source: std::io::Error },
    #[snafu(display("failed to decode channel extended data type"))]
    DecodeExtendedDataType { source: std::io::Error },
    #[snafu(display("failed to decode channel extended data length"))]
    DecodeExtendedData { source: std::io::Error },
    #[snafu(display("failed to decode channel request type string"))]
    DecodeRequestType { source: CodecError },
    #[snafu(display("failed to decode channel want_reply flag"))]
    DecodeWantReply { source: CodecError },
    #[snafu(display("unexpected channel message type {message_type}"))]
    UnexpectedMessageType { message_type: VarInt },
    #[snafu(display("unexpected want_reply=true channel request '{request_type}' on reader-only channel"))]
    UnexpectedWantReply { request_type: SshString },
}

/// Error from [`ChannelResponder::respond_success`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RespondChannelSuccessError<RE: std::error::Error + Send + Sync + 'static> {
    #[snafu(display("failed to encode channel success message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode channel success response payload"))]
    EncodePayload { source: RE },
    #[snafu(display("failed to flush channel stream after success response"))]
    Flush { source: std::io::Error },
}

/// Error from [`ChannelResponder::respond_failure`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RespondChannelFailureError {
    #[snafu(display("failed to encode channel failure message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to flush channel stream after failure response"))]
    Flush { source: std::io::Error },
}

/// Error from [`SshChannelWriter::data`] and [`SshChannelWriter::data_from`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteDataError {
    #[snafu(display("failed to encode channel data message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode channel data length"))]
    EncodeLength { source: std::io::Error },
    #[snafu(display("failed to write channel data payload"))]
    WritePayload { source: std::io::Error },
    #[snafu(display("source yielded {actual} bytes but {expected} were declared"))]
    ShortSource { expected: u64, actual: u64 },
    #[snafu(display("failed to flush channel stream after data"))]
    Flush { source: std::io::Error },
}

/// Error from [`SshChannelWriter::extended_data`] and [`SshChannelWriter::extended_data_from`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteExtendedDataError {
    #[snafu(display("failed to encode extended data message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode extended data type field"))]
    EncodeDataType { source: std::io::Error },
    #[snafu(display("failed to encode extended data length"))]
    EncodeLength { source: std::io::Error },
    #[snafu(display("failed to write extended data payload"))]
    WritePayload { source: std::io::Error },
    #[snafu(display("source yielded {actual} bytes but {expected} were declared"))]
    ShortSource { expected: u64, actual: u64 },
    #[snafu(display("failed to flush channel stream after extended data"))]
    Flush { source: std::io::Error },
}

/// Error from [`SshChannelWriter::eof`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteChannelEofError {
    #[snafu(display("failed to encode channel EOF message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to flush channel stream after EOF"))]
    Flush { source: std::io::Error },
}

/// Error from [`SshChannelWriter::close`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteChannelCloseError {
    #[snafu(display("failed to encode channel close message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to flush channel stream after close"))]
    Flush { source: std::io::Error },
}

/// Error reading a channel open response (confirmation or failure).
///
/// Used by [`super::read_channel_open_response`] and [`super::Conversation::open_channel`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::conversation)))]
pub enum AwaitOpenError {
    #[snafu(display("failed to decode channel open response message type"))]
    DecodeMessageType { source: std::io::Error },
    #[snafu(display("failed to decode max message size from confirmation"))]
    DecodeMaxMessageSize { source: std::io::Error },
    #[snafu(display("failed to decode open failure reason code"))]
    DecodeReasonCode { source: std::io::Error },
    #[snafu(display("failed to decode open failure description"))]
    DecodeDescription { source: CodecError },
    #[snafu(display("channel open was rejected"))]
    Rejected { failure: ChannelOpenFailure },
    #[snafu(display("unexpected channel open response message type {message_type}"))]
    UnexpectedMessageType { message_type: VarInt },
}

/// Error from [`PendingChannel::accept`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteChannelOpenConfirmationError {
    #[snafu(display("failed to encode channel open confirmation message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode max message size"))]
    EncodeMaxMessageSize { source: std::io::Error },
    #[snafu(display("failed to flush channel stream after confirmation"))]
    Flush { source: std::io::Error },
}

/// Error from [`PendingChannel::reject`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteChannelOpenFailureError {
    #[snafu(display("failed to encode channel open failure message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode open failure reason code"))]
    EncodeReasonCode { source: std::io::Error },
    #[snafu(display("failed to encode open failure description"))]
    EncodeDescription { source: CodecError },
    #[snafu(display("failed to flush channel stream after failure"))]
    Flush { source: std::io::Error },
}

// ===========================================================================
// Incoming channel
// ===========================================================================

/// An incoming channel whose header has been read and validated.
///
/// The caller inspects [`channel_type`](Self::channel_type) to determine what
/// kind of channel was opened, then calls [`decode_payload`](Self::decode_payload)
/// to decode the channel-type-specific payload and obtain a [`PendingChannel`]
/// that can be accepted or rejected.
///
/// Unlike global requests, channels have independent streams. Dropping this
/// struct simply closes the streams — it does **not** poison the session.
pub struct IncomingChannel<M: ManageSessionStream> {
    channel_type: SshString,
    max_message_size: VarInt,
    reader: M::StreamReader,
    writer: M::StreamWriter,
}

impl<M: ManageSessionStream> IncomingChannel<M> {
    /// Create an `IncomingChannel` from its constituent parts.
    ///
    /// Used by [`super::Conversation::accept_channel`].
    pub(super) fn new(
        channel_type: SshString,
        max_message_size: VarInt,
        reader: M::StreamReader,
        writer: M::StreamWriter,
    ) -> Self {
        Self {
            channel_type,
            max_message_size,
            reader,
            writer,
        }
    }

    /// The SSH channel type string sent by the remote (e.g. `"session"`).
    pub fn channel_type(&self) -> &SshString {
        &self.channel_type
    }

    /// The maximum message size for this channel.
    pub fn max_message_size(&self) -> VarInt {
        self.max_message_size
    }

    /// Decode the channel-type-specific payload from the stream, consuming
    /// `self`.
    ///
    /// Returns the decoded payload together with a [`PendingChannel`] that
    /// must be accepted or rejected to complete the channel handshake.
    pub async fn decode_payload<T, DE>(
        mut self,
    ) -> Result<(T, PendingChannel<M::StreamReader, M::StreamWriter>), DE>
    where
        T: for<'r> DecodeFrom<&'r mut M::StreamReader, Error = DE>,
    {
        let value = T::decode_from(&mut self.reader).await?;
        Ok((
            value,
            PendingChannel {
                reader: self.reader,
                writer: self.writer,
            },
        ))
    }

    /// Skip payload decoding and return a [`PendingChannel`] directly.
    ///
    /// Useful for channel types that carry no additional payload (e.g.
    /// `"session"` channels).
    pub fn skip_payload(self) -> PendingChannel<M::StreamReader, M::StreamWriter> {
        PendingChannel {
            reader: self.reader,
            writer: self.writer,
        }
    }

    /// Consume and return the raw stream pair without decoding anything.
    ///
    /// Useful when passing streams to a handler that performs its own payload
    /// decoding (e.g. direct forwarding handlers).
    pub fn into_raw_parts(self) -> (M::StreamReader, M::StreamWriter) {
        (self.reader, self.writer)
    }
}

// ===========================================================================
// PendingChannel — awaiting accept/reject decision
// ===========================================================================

/// A channel that has been opened by the remote but not yet confirmed or
/// rejected locally.
///
/// Obtained from [`IncomingChannel::decode_payload`] or
/// [`IncomingChannel::skip_payload`]. Call [`accept`](Self::accept) to send
/// a confirmation and obtain the raw stream pair, or [`reject`](Self::reject)
/// to send a failure.
///
/// After [`accept`](Self::accept), the returned streams carry:
/// - **Raw bytes** for forwarding channels (direct-tcp, forwarded-tcp, etc.)
/// - **SSH messages** for session channels (wrap in [`SshChannelWriter`] /
///   [`SshChannelReader`])
pub struct PendingChannel<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> PendingChannel<R, W> {
    /// Create a `PendingChannel` from pre-decoded reader and writer.
    ///
    /// Use this when the channel-type-specific payload has already been
    /// decoded from the reader at a different layer (e.g. the direct
    /// forwarding handler).
    pub fn from_raw_parts(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R, W: AsyncWrite + Unpin + Send> PendingChannel<R, W> {
    /// Send a channel open confirmation and return the established channel.
    pub async fn accept(
        mut self,
        max_message_size: VarInt,
    ) -> Result<SshChannel<R, W>, WriteChannelOpenConfirmationError> {
        use write_channel_open_confirmation_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .encode_one(max_message_size)
            .await
            .context(EncodeMaxMessageSizeSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(SshChannel::new(self.reader, self.writer))
    }

    /// Send a channel open failure. The channel is dead after this.
    pub async fn reject(
        mut self,
        reason_code: VarInt,
        description: SshString,
    ) -> Result<(), WriteChannelOpenFailureError> {
        use write_channel_open_failure_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_OPEN_FAILURE)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .encode_one(reason_code)
            .await
            .context(EncodeReasonCodeSnafu)?;
        self.writer
            .encode_one(description)
            .await
            .context(EncodeDescriptionSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }
}

// ===========================================================================
// SshChannelReader — read-only half of an SSH channel
// ===========================================================================

/// Read-only half of an SSH channel.
///
/// Obtained from [`SshChannel::into_split`]. Provides event reading
/// without access to the writer. Channel requests with `want_reply=true`
/// are rejected as [`ReadChannelEventError::UnexpectedWantReply`] since
/// there is no writer to send the reply.
#[derive(Debug)]
pub struct SshChannelReader<R>(R);

impl<R> SshChannelReader<R> {
    /// Consume the reader wrapper and return the inner stream.
    pub fn into_inner(self) -> R {
        self.0
    }
}

impl<R: AsyncRead + Unpin + Send> SshChannelReader<R> {
    /// Read the next event from the channel stream.
    ///
    /// Returns [`ReadChannelEventError::UnexpectedWantReply`] if a channel
    /// request with `want_reply=true` is received, since the reader half
    /// has no writer to send a reply.
    pub async fn next_event(&mut self) -> Result<ReaderEvent<'_, R>, ReadChannelEventError> {
        use read_channel_event_error::*;

        let msg_type: VarInt = self.0.decode_one().await.context(DecodeMessageTypeSnafu)?;

        match msg_type {
            SSH_MSG_CHANNEL_DATA => {
                let len: VarInt = self.0.decode_one().await.context(DecodeDataSnafu)?;
                Ok(ReaderEvent::Data(ChannelDataRead {
                    reader: &mut self.0,
                    remaining: len.into_inner(),
                }))
            }
            SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let data_type: VarInt =
                    self.0.decode_one().await.context(DecodeExtendedDataTypeSnafu)?;
                let len: VarInt = self.0.decode_one().await.context(DecodeExtendedDataSnafu)?;
                Ok(ReaderEvent::ExtendedData {
                    data_type,
                    data: ChannelDataRead {
                        reader: &mut self.0,
                        remaining: len.into_inner(),
                    },
                })
            }
            SSH_MSG_CHANNEL_REQUEST => {
                let request_type: SshString =
                    self.0.decode_one().await.context(DecodeRequestTypeSnafu)?;
                let want_reply: SshBool =
                    self.0.decode_one().await.context(DecodeWantReplySnafu)?;
                if want_reply.0 {
                    return Err(ReadChannelEventError::UnexpectedWantReply { request_type });
                }
                Ok(ReaderEvent::Notice(IncomingChannelNotice {
                    request_type,
                    reader: &mut self.0,
                }))
            }
            SSH_MSG_CHANNEL_SUCCESS => Ok(ReaderEvent::Success),
            SSH_MSG_CHANNEL_FAILURE => Ok(ReaderEvent::Failure),
            SSH_MSG_CHANNEL_EOF => Ok(ReaderEvent::Eof),
            SSH_MSG_CHANNEL_CLOSE => Ok(ReaderEvent::Close),
            other => Err(ReadChannelEventError::UnexpectedMessageType {
                message_type: other,
            }),
        }
    }
}

// ===========================================================================
// SshChannelWriter — write-only half of an SSH channel
// ===========================================================================

/// Write-only half of an SSH channel.
///
/// Obtained from [`SshChannel::into_split`]. Provides all write operations:
/// data, extended data, EOF, close, and channel notices.
#[derive(Debug)]
pub struct SshChannelWriter<W>(W);

impl<W> SshChannelWriter<W> {
    /// Consume the writer wrapper and return the inner stream.
    pub fn into_inner(self) -> W {
        self.0
    }

    /// Borrow the underlying writer.
    pub fn writer(&self) -> &W {
        &self.0
    }

    /// Mutably borrow the underlying writer.
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.0
    }
}

impl<W: AsyncWrite + Unpin + Send> SshChannelWriter<W> {
    /// Write channel data from a byte slice.
    pub async fn data(&mut self, data: &[u8]) -> Result<(), WriteDataError> {
        use write_data_error::*;

        let len = VarInt::try_from(data.len() as u64).expect("data length exceeds VarInt range");

        self.0
            .encode_one(SSH_MSG_CHANNEL_DATA)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.0.encode_one(len).await.context(EncodeLengthSnafu)?;
        self.0
            .write_all(data)
            .await
            .context(WritePayloadSnafu)?;
        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write channel data by copying from an [`AsyncRead`] source.
    ///
    /// Writes the message header (type + length), then copies exactly `length`
    /// bytes from `source` to the channel stream. This avoids buffering the
    /// entire payload in memory.
    pub async fn data_from<S: AsyncRead + Unpin>(
        &mut self,
        source: &mut S,
        length: u64,
    ) -> Result<(), WriteDataError> {
        use write_data_error::*;

        let len = VarInt::try_from(length).expect("data length exceeds VarInt range");

        self.0
            .encode_one(SSH_MSG_CHANNEL_DATA)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.0.encode_one(len).await.context(EncodeLengthSnafu)?;

        let copied = tokio::io::copy(&mut source.take(length), &mut self.0)
            .await
            .context(WritePayloadSnafu)?;
        snafu::ensure!(
            copied == length,
            ShortSourceSnafu {
                expected: length,
                actual: copied
            }
        );

        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write extended channel data from a byte slice.
    pub async fn extended_data(
        &mut self,
        data_type: VarInt,
        data: &[u8],
    ) -> Result<(), WriteExtendedDataError> {
        use write_extended_data_error::*;

        let len = VarInt::try_from(data.len() as u64).expect("data length exceeds VarInt range");

        self.0
            .encode_one(SSH_MSG_CHANNEL_EXTENDED_DATA)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.0
            .encode_one(data_type)
            .await
            .context(EncodeDataTypeSnafu)?;
        self.0.encode_one(len).await.context(EncodeLengthSnafu)?;
        self.0
            .write_all(data)
            .await
            .context(WritePayloadSnafu)?;
        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write extended channel data by copying from an [`AsyncRead`] source.
    pub async fn extended_data_from<S: AsyncRead + Unpin>(
        &mut self,
        data_type: VarInt,
        source: &mut S,
        length: u64,
    ) -> Result<(), WriteExtendedDataError> {
        use write_extended_data_error::*;

        let len = VarInt::try_from(length).expect("data length exceeds VarInt range");

        self.0
            .encode_one(SSH_MSG_CHANNEL_EXTENDED_DATA)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.0
            .encode_one(data_type)
            .await
            .context(EncodeDataTypeSnafu)?;
        self.0.encode_one(len).await.context(EncodeLengthSnafu)?;

        let copied = tokio::io::copy(&mut source.take(length), &mut self.0)
            .await
            .context(WritePayloadSnafu)?;
        snafu::ensure!(
            copied == length,
            ShortSourceSnafu {
                expected: length,
                actual: copied
            }
        );

        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write channel EOF (`SSH_MSG_CHANNEL_EOF`).
    pub async fn eof(&mut self) -> Result<(), WriteChannelEofError> {
        use write_channel_eof_error::*;

        self.0
            .encode_one(SSH_MSG_CHANNEL_EOF)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write channel close (`SSH_MSG_CHANNEL_CLOSE`).
    pub async fn close(&mut self) -> Result<(), WriteChannelCloseError> {
        use write_channel_close_error::*;

        self.0
            .encode_one(SSH_MSG_CHANNEL_CLOSE)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Send a channel notification (no reply expected).
    pub async fn notice<N, PE>(&mut self, notice: &N) -> Result<(), SendChannelNoticeError<PE>>
    where
        N: NotifyChannelRequest,
        PE: std::error::Error + Send + Sync + 'static,
        for<'a> N::Payload: EncodeInto<&'a mut W, Output = (), Error = PE>,
    {
        use send_channel_notice_error::*;

        self.0
            .encode_one(SSH_MSG_CHANNEL_REQUEST)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.0
            .encode_one(notice.request_type())
            .await
            .context(EncodeRequestTypeSnafu)?;
        self.0
            .encode_one(SshBool(false))
            .await
            .context(EncodeWantReplySnafu)?;
        notice
            .payload()
            .clone()
            .encode_into(&mut self.0)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut self.0)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }
}

// ===========================================================================
// SshChannel — unified channel type
// ===========================================================================

/// Unified SSH channel wrapping both read and write halves.
///
/// Provides methods for reading events ([`next_event`](Self::next_event)),
/// writing data ([`data`](Self::data), [`data_from`](Self::data_from)),
/// sending requests, and channel lifecycle management.
///
/// Only meaningful for channel types that use SSH message framing (e.g.
/// `"session"`). Forwarding channels should use raw streams directly via
/// [`into_inner`](Self::into_inner).
#[derive(Debug)]
pub struct SshChannel<R, W> {
    reader: SshChannelReader<R>,
    writer: SshChannelWriter<W>,
}

impl<R, W> SshChannel<R, W> {
    /// Create from raw reader and writer.
    ///
    /// The channel must already be established (open/accept handshake done).
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: SshChannelReader(reader),
            writer: SshChannelWriter(writer),
        }
    }

    /// Consume the channel and return the raw stream pair.
    pub fn into_inner(self) -> (R, W) {
        (self.reader.into_inner(), self.writer.into_inner())
    }

    /// Consume the channel and return the raw stream pair.
    #[deprecated(note = "renamed to `into_inner`")]
    pub fn into_parts(self) -> (R, W) {
        self.into_inner()
    }

    /// Split the channel into its read and write halves.
    pub fn into_split(self) -> (SshChannelReader<R>, SshChannelWriter<W>) {
        (self.reader, self.writer)
    }

    /// Borrow the underlying reader.
    pub fn reader(&self) -> &R {
        &self.reader.0
    }

    /// Mutably borrow the underlying reader.
    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader.0
    }

    /// Borrow the underlying writer.
    pub fn writer(&self) -> &W {
        &self.writer.0
    }

    /// Mutably borrow the underlying writer.
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer.0
    }
}

impl<R: AsyncRead + Unpin + Send, W: AsyncWrite + Unpin + Send> SshChannel<R, W> {
    // --- Read events ---

    /// Read the next event from the channel stream.
    ///
    /// Unlike [`SshChannelReader::next_event`], this returns
    /// [`ChannelEvent`] which includes [`IncomingChannelRequest`] with
    /// writer access for sending replies.
    pub async fn next_event(&mut self) -> Result<ChannelEvent<'_, R, W>, ReadChannelEventError> {
        use read_channel_event_error::*;

        let msg_type: VarInt = self
            .reader
            .0
            .decode_one()
            .await
            .context(DecodeMessageTypeSnafu)?;

        match msg_type {
            SSH_MSG_CHANNEL_DATA => {
                let len: VarInt = self.reader.0.decode_one().await.context(DecodeDataSnafu)?;
                Ok(ChannelEvent::Data(ChannelDataRead {
                    reader: &mut self.reader.0,
                    remaining: len.into_inner(),
                }))
            }
            SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let data_type: VarInt = self
                    .reader
                    .0
                    .decode_one()
                    .await
                    .context(DecodeExtendedDataTypeSnafu)?;
                let len: VarInt = self
                    .reader
                    .0
                    .decode_one()
                    .await
                    .context(DecodeExtendedDataSnafu)?;
                Ok(ChannelEvent::ExtendedData {
                    data_type,
                    data: ChannelDataRead {
                        reader: &mut self.reader.0,
                        remaining: len.into_inner(),
                    },
                })
            }
            SSH_MSG_CHANNEL_REQUEST => {
                let request_type: SshString = self
                    .reader
                    .0
                    .decode_one()
                    .await
                    .context(DecodeRequestTypeSnafu)?;
                let want_reply: SshBool = self
                    .reader
                    .0
                    .decode_one()
                    .await
                    .context(DecodeWantReplySnafu)?;
                let SshChannel { reader, writer } = self;
                Ok(ChannelEvent::Request(IncomingChannelRequest {
                    request_type,
                    want_reply: want_reply.0,
                    reader: &mut reader.0,
                    writer: &mut writer.0,
                }))
            }
            SSH_MSG_CHANNEL_SUCCESS => Ok(ChannelEvent::Success),
            SSH_MSG_CHANNEL_FAILURE => Ok(ChannelEvent::Failure),
            SSH_MSG_CHANNEL_EOF => Ok(ChannelEvent::Eof),
            SSH_MSG_CHANNEL_CLOSE => Ok(ChannelEvent::Close),
            other => Err(ReadChannelEventError::UnexpectedMessageType {
                message_type: other,
            }),
        }
    }

    // --- Writer method delegates ---

    /// Write channel data from a byte slice.
    pub async fn data(&mut self, data: &[u8]) -> Result<(), WriteDataError> {
        self.writer.data(data).await
    }

    /// Write channel data by copying from an [`AsyncRead`] source.
    ///
    /// Writes the message header (type + length), then copies exactly `length`
    /// bytes from `source` to the channel stream. This avoids buffering the
    /// entire payload in memory.
    pub async fn data_from<S: AsyncRead + Unpin>(
        &mut self,
        source: &mut S,
        length: u64,
    ) -> Result<(), WriteDataError> {
        self.writer.data_from(source, length).await
    }

    /// Write extended channel data from a byte slice.
    pub async fn extended_data(
        &mut self,
        data_type: VarInt,
        data: &[u8],
    ) -> Result<(), WriteExtendedDataError> {
        self.writer.extended_data(data_type, data).await
    }

    /// Write extended channel data by copying from an [`AsyncRead`] source.
    pub async fn extended_data_from<S: AsyncRead + Unpin>(
        &mut self,
        data_type: VarInt,
        source: &mut S,
        length: u64,
    ) -> Result<(), WriteExtendedDataError> {
        self.writer.extended_data_from(data_type, source, length).await
    }

    /// Write channel EOF (`SSH_MSG_CHANNEL_EOF`).
    pub async fn eof(&mut self) -> Result<(), WriteChannelEofError> {
        self.writer.eof().await
    }

    /// Write channel close (`SSH_MSG_CHANNEL_CLOSE`).
    pub async fn close(&mut self) -> Result<(), WriteChannelCloseError> {
        self.writer.close().await
    }

    /// Send a channel notification (no reply expected).
    pub async fn notice<N, PE>(&mut self, notice: &N) -> Result<(), SendChannelNoticeError<PE>>
    where
        N: NotifyChannelRequest,
        PE: std::error::Error + Send + Sync + 'static,
        for<'a> N::Payload: EncodeInto<&'a mut W, Output = (), Error = PE>,
    {
        self.writer.notice(notice).await
    }

    // --- Request operations ---

    /// Send a channel request that expects a reply, reading the response
    /// from the channel's read half.
    pub async fn request<Req, PE, SE>(
        &mut self,
        request: &Req,
    ) -> Result<Req::Success, SendChannelRequestError<PE, SE>>
    where
        Req: WantReplyChannelRequest,
        PE: std::error::Error + Send + Sync + 'static,
        SE: std::error::Error + Send + Sync + 'static,
        for<'a> Req::Payload: EncodeInto<&'a mut W, Output = (), Error = PE>,
        for<'a> Req::Success: DecodeFrom<&'a mut R, Error = SE>,
    {
        use send_channel_request_error::*;

        self.writer
            .0
            .encode_one(SSH_MSG_CHANNEL_REQUEST)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .0
            .encode_one(request.request_type())
            .await
            .context(EncodeRequestTypeSnafu)?;
        self.writer
            .0
            .encode_one(SshBool(true))
            .await
            .context(EncodeWantReplySnafu)?;
        request
            .payload()
            .clone()
            .encode_into(&mut self.writer.0)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut self.writer.0)
            .await
            .context(FlushSnafu)?;

        let msg_type: VarInt = self
            .reader
            .0
            .decode_one()
            .await
            .context(DecodeResponseTypeSnafu)?;

        match msg_type {
            SSH_MSG_CHANNEL_SUCCESS => {
                let success = Req::Success::decode_from(&mut self.reader.0)
                    .await
                    .context(DecodeSuccessSnafu)?;
                Ok(success)
            }
            SSH_MSG_CHANNEL_FAILURE => Err(SendChannelRequestError::Rejected),
            other => Err(SendChannelRequestError::UnexpectedResponseType {
                message_type: other,
            }),
        }
    }
}

// ===========================================================================
// ChannelDataRead — bounded async reader for channel data
// ===========================================================================

/// Bounded reader for a channel data payload.
///
/// Returned by [`ChannelEvent::Data`], [`ChannelEvent::ExtendedData`],
/// [`ReaderEvent::Data`], and [`ReaderEvent::ExtendedData`].
/// Reads at most [`remaining`](Self::remaining) bytes from the underlying
/// channel stream. Implements [`AsyncRead`].
///
/// Dropping without reading all bytes is safe but leaves the channel stream
/// in an inconsistent state — subsequent [`next_event`](SshChannel::next_event)
/// calls will produce garbage. The caller should read all bytes or close the
/// channel.
pub struct ChannelDataRead<'c, R> {
    reader: &'c mut R,
    remaining: u64,
}

impl<R> ChannelDataRead<'_, R> {
    /// Remaining bytes in this data payload.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl<R: AsyncRead + Unpin> ChannelDataRead<'_, R> {
    /// Read all remaining data into a `Vec<u8>`.
    ///
    /// Convenience method for small payloads where streaming is unnecessary.
    pub async fn read_all(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![0u8; self.remaining as usize];
        tokio::io::AsyncReadExt::read_exact(self, &mut buf).await?;
        Ok(buf)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ChannelDataRead<'_, R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(Ok(()));
        }

        // Limit the read to the remaining bytes.
        let max_read = (self.remaining as usize).min(buf.remaining());
        let mut limited_buf = buf.take(max_read);

        let before = limited_buf.filled().len();
        let result = std::pin::Pin::new(&mut *self.reader).poll_read(cx, &mut limited_buf);

        let bytes_read = limited_buf.filled().len() - before;
        self.remaining -= bytes_read as u64;

        // Advance the outer buf by the same amount.
        // SAFETY: limited_buf wrote into the same backing buffer as buf,
        // so those bytes are already initialized.
        unsafe { buf.assume_init(buf.filled().len() + bytes_read) };
        buf.advance(bytes_read);

        result
    }
}

// ===========================================================================
// Channel event types
// ===========================================================================

/// An event read from a channel stream via [`SshChannel::next_event`].
///
/// The lifetime `'c` ties the event to the channel borrow, ensuring the
/// caller processes or drops the event before reading the next one.
pub enum ChannelEvent<'c, R, W> {
    /// Channel data (`SSH_MSG_CHANNEL_DATA`) with streaming read.
    Data(ChannelDataRead<'c, R>),
    /// Extended channel data (`SSH_MSG_CHANNEL_EXTENDED_DATA`) with streaming read.
    ExtendedData {
        data_type: VarInt,
        data: ChannelDataRead<'c, R>,
    },
    /// A channel request with deferred payload decode.
    Request(IncomingChannelRequest<'c, R, W>),
    /// Channel success (`SSH_MSG_CHANNEL_SUCCESS`).
    Success,
    /// Channel failure (`SSH_MSG_CHANNEL_FAILURE`).
    Failure,
    /// End of file (`SSH_MSG_CHANNEL_EOF`).
    Eof,
    /// Channel close (`SSH_MSG_CHANNEL_CLOSE`).
    Close,
}

/// An event read from a channel stream via [`SshChannelReader::next_event`].
///
/// Like [`ChannelEvent`] but without writer access. Channel requests with
/// `want_reply=false` are returned as [`ReaderEvent::Notice`]; requests
/// with `want_reply=true` cause an error.
pub enum ReaderEvent<'c, R> {
    /// Channel data (`SSH_MSG_CHANNEL_DATA`) with streaming read.
    Data(ChannelDataRead<'c, R>),
    /// Extended channel data (`SSH_MSG_CHANNEL_EXTENDED_DATA`) with streaming read.
    ExtendedData {
        data_type: VarInt,
        data: ChannelDataRead<'c, R>,
    },
    /// A channel notice (`want_reply=false`) with deferred payload decode.
    Notice(IncomingChannelNotice<'c, R>),
    /// Channel success (`SSH_MSG_CHANNEL_SUCCESS`).
    Success,
    /// Channel failure (`SSH_MSG_CHANNEL_FAILURE`).
    Failure,
    /// End of file (`SSH_MSG_CHANNEL_EOF`).
    Eof,
    /// Channel close (`SSH_MSG_CHANNEL_CLOSE`).
    Close,
}

// ---------------------------------------------------------------------------
// IncomingChannelRequest — deferred payload decode with writer access
// ---------------------------------------------------------------------------

/// An incoming channel request with deferred payload decoding.
///
/// The header (request type and want_reply flag) has been read; the payload
/// remains on the stream. Call [`decode_payload`](Self::decode_payload) to
/// decode it.
///
/// Holds split borrows to both the reader (for decoding) and writer (for
/// responding). After [`decode_payload`](Self::decode_payload), the reader
/// borrow is released and a [`ChannelResponder`] is returned if the remote
/// expects a reply.
pub struct IncomingChannelRequest<'c, R, W> {
    request_type: SshString,
    want_reply: bool,
    reader: &'c mut R,
    writer: &'c mut W,
}

impl<'c, R, W> IncomingChannelRequest<'c, R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    /// The SSH request type string (e.g. `"pty-req"`, `"exec"`).
    pub fn request_type(&self) -> &SshString {
        &self.request_type
    }

    /// Whether the remote expects a reply for this request.
    pub fn want_reply(&self) -> bool {
        self.want_reply
    }

    /// Decode the request payload directly from the channel stream.
    ///
    /// Consumes `self`. If `want_reply` is true, returns a
    /// [`ChannelResponder`] that holds a reference to the writer and can send
    /// the reply directly. If `want_reply` is false, returns `None`.
    pub async fn decode_payload<T, DE>(self) -> Result<(T, Option<ChannelResponder<'c, W>>), DE>
    where
        T: for<'r> DecodeFrom<&'r mut R, Error = DE>,
    {
        let value = T::decode_from(self.reader).await?;
        let responder = if self.want_reply {
            Some(ChannelResponder {
                writer: self.writer,
            })
        } else {
            None
        };
        Ok((value, responder))
    }
}

// ---------------------------------------------------------------------------
// IncomingChannelNotice — channel request with want_reply=false (reader-only)
// ---------------------------------------------------------------------------

/// An incoming channel notice (`want_reply=false`) with deferred payload
/// decoding.
///
/// Returned by [`ReaderEvent::Notice`] when the reader-only half receives a
/// channel request that does not expect a reply. The payload remains on the
/// stream until [`decode_payload`](Self::decode_payload) is called.
pub struct IncomingChannelNotice<'c, R> {
    request_type: SshString,
    reader: &'c mut R,
}

impl<'c, R: AsyncRead + Unpin + Send> IncomingChannelNotice<'c, R> {
    /// The SSH request type string (e.g. `"signal"`, `"exit-status"`).
    pub fn request_type(&self) -> &SshString {
        &self.request_type
    }

    /// Decode the notice payload directly from the channel stream.
    pub async fn decode_payload<T, DE>(self) -> Result<T, DE>
    where
        T: for<'r> DecodeFrom<&'r mut R, Error = DE>,
    {
        T::decode_from(self.reader).await
    }
}

// ---------------------------------------------------------------------------
// ChannelResponder — send success/failure for a channel request
// ---------------------------------------------------------------------------

/// A responder for an incoming channel request that expects a reply.
///
/// Obtained from [`IncomingChannelRequest::decode_payload`] when
/// `want_reply` is true. Holds a mutable reference to the channel writer,
/// ensuring the reply is sent on the correct stream.
///
/// Dropping without responding is silent (the remote will time out or
/// interpret the absence as failure). This does **not** poison the session —
/// channels are independent.
pub struct ChannelResponder<'c, W> {
    writer: &'c mut W,
}

impl<W: AsyncWrite + Unpin + Send> ChannelResponder<'_, W> {
    /// Send a success response, optionally with a payload.
    pub async fn respond_success<P, RE>(
        self,
        response: P,
    ) -> Result<(), RespondChannelSuccessError<RE>>
    where
        RE: std::error::Error + Send + Sync + 'static,
        for<'a> P: EncodeInto<&'a mut W, Output = (), Error = RE>,
    {
        use respond_channel_success_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_SUCCESS)
            .await
            .context(EncodeMessageTypeSnafu)?;
        response
            .encode_into(self.writer)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Send a failure response.
    pub async fn respond_failure(self) -> Result<(), RespondChannelFailureError> {
        use respond_channel_failure_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_FAILURE)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }
}
