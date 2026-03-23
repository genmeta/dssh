use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::channel::ChannelOpenFailure;
use crate::codec::{CodecError, SshBool, SshBytes, SshString};

use super::{
    ManageSessionStream, NotifyChannelRequest, WantReplyChannelRequest,
    SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EOF,
    SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_FAILURE,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE,
    SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS,
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

/// Error from [`SshChannelWriter::request`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SendChannelRequestError<PE: std::error::Error + Send + Sync + 'static, SE: std::error::Error + Send + Sync + 'static> {
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

/// Error from [`SshChannelReader::next_event`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadChannelEventError {
    #[snafu(display("failed to decode channel message type"))]
    DecodeMessageType { source: std::io::Error },
    #[snafu(display("failed to decode channel data"))]
    DecodeData { source: CodecError },
    #[snafu(display("failed to decode channel extended data type"))]
    DecodeExtendedDataType { source: std::io::Error },
    #[snafu(display("failed to decode channel extended data"))]
    DecodeExtendedData { source: CodecError },
    #[snafu(display("failed to decode channel request type string"))]
    DecodeRequestType { source: CodecError },
    #[snafu(display("failed to decode channel want_reply flag"))]
    DecodeWantReply { source: CodecError },
    #[snafu(display("unexpected channel message type {message_type}"))]
    UnexpectedMessageType { message_type: VarInt },
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

/// Error from [`SshChannelWriter::data`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteChannelDataError {
    #[snafu(display("failed to encode channel data message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode channel data payload"))]
    EncodeData { source: CodecError },
    #[snafu(display("failed to flush channel stream after data"))]
    Flush { source: std::io::Error },
}

/// Error from [`SshChannelWriter::extended_data`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteChannelExtendedDataError {
    #[snafu(display("failed to encode extended data message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode extended data type field"))]
    EncodeDataType { source: std::io::Error },
    #[snafu(display("failed to encode extended data payload"))]
    EncodeData { source: CodecError },
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
        Self { channel_type, max_message_size, reader, writer }
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
        Ok((value, PendingChannel { reader: self.reader, writer: self.writer }))
    }

    /// Skip payload decoding and return a [`PendingChannel`] directly.
    ///
    /// Useful for channel types that carry no additional payload (e.g.
    /// `"session"` channels).
    pub fn skip_payload(self) -> PendingChannel<M::StreamReader, M::StreamWriter> {
        PendingChannel { reader: self.reader, writer: self.writer }
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
    /// Send a channel open confirmation and return the raw stream pair.
    pub async fn accept(
        mut self,
        max_message_size: VarInt,
    ) -> Result<(R, W), WriteChannelOpenConfirmationError> {
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
        Ok((self.reader, self.writer))
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
// SshChannelWriter — typed wrapper for channel write operations
// ===========================================================================

/// Typed wrapper around a channel's write half for SSH message IO.
///
/// Constructed via [`new`](Self::new) after channel establishment is complete.
/// Provides methods for sending SSH channel messages (data, extended data,
/// EOF, close, request, notice). Only meaningful for channel types that use
/// SSH message framing (e.g. `"session"`). Forwarding channels should use
/// raw streams directly.
pub struct SshChannelWriter<W> {
    writer: W,
}

impl<W: AsyncWrite + Unpin + Send> SshChannelWriter<W> {
    /// Wrap a writer for SSH channel message IO.
    ///
    /// The channel must already be established (open/accept handshake done).
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    // --- Data operations ---

    /// Write channel data (`SSH_MSG_CHANNEL_DATA`).
    pub async fn data(&mut self, data: SshBytes) -> Result<(), WriteChannelDataError> {
        use write_channel_data_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_DATA)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .encode_one(data)
            .await
            .context(EncodeDataSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write channel extended data (`SSH_MSG_CHANNEL_EXTENDED_DATA`).
    ///
    /// `data_type` distinguishes the data substream (e.g. `1` for stderr
    /// per RFC 4254 Section 5.2).
    pub async fn extended_data(
        &mut self,
        data_type: VarInt,
        data: SshBytes,
    ) -> Result<(), WriteChannelExtendedDataError> {
        use write_channel_extended_data_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_EXTENDED_DATA)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .encode_one(data_type)
            .await
            .context(EncodeDataTypeSnafu)?;
        self.writer
            .encode_one(data)
            .await
            .context(EncodeDataSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write channel EOF (`SSH_MSG_CHANNEL_EOF`).
    pub async fn eof(&mut self) -> Result<(), WriteChannelEofError> {
        use write_channel_eof_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_EOF)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Write channel close (`SSH_MSG_CHANNEL_CLOSE`).
    pub async fn close(&mut self) -> Result<(), WriteChannelCloseError> {
        use write_channel_close_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_CLOSE)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    // --- Request operations ---

    /// Send a channel request that expects a reply, reading the response
    /// from the given [`SshChannelReader`].
    pub async fn request<R, Req, PE, SE>(
        &mut self,
        reader: &mut SshChannelReader<R>,
        request: &Req,
    ) -> Result<Req::Success, SendChannelRequestError<PE, SE>>
    where
        R: AsyncRead + Unpin + Send,
        Req: WantReplyChannelRequest,
        PE: std::error::Error + Send + Sync + 'static,
        SE: std::error::Error + Send + Sync + 'static,
        for<'a> Req::Payload: EncodeInto<&'a mut W, Output = (), Error = PE>,
        for<'a> Req::Success: DecodeFrom<&'a mut R, Error = SE>,
    {
        use send_channel_request_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_REQUEST)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .encode_one(request.request_type())
            .await
            .context(EncodeRequestTypeSnafu)?;
        self.writer
            .encode_one(SshBool(true))
            .await
            .context(EncodeWantReplySnafu)?;
        request
            .payload()
            .clone()
            .encode_into(&mut self.writer)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;

        let msg_type: VarInt = reader
            .reader
            .decode_one()
            .await
            .context(DecodeResponseTypeSnafu)?;

        match msg_type {
            SSH_MSG_CHANNEL_SUCCESS => {
                let success = Req::Success::decode_from(&mut reader.reader)
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

    /// Send a channel notification (no reply expected).
    pub async fn notice<N, PE>(
        &mut self,
        notice: &N,
    ) -> Result<(), SendChannelNoticeError<PE>>
    where
        N: NotifyChannelRequest,
        PE: std::error::Error + Send + Sync + 'static,
        for<'a> N::Payload: EncodeInto<&'a mut W, Output = (), Error = PE>,
    {
        use send_channel_notice_error::*;

        self.writer
            .encode_one(SSH_MSG_CHANNEL_REQUEST)
            .await
            .context(EncodeMessageTypeSnafu)?;
        self.writer
            .encode_one(notice.request_type())
            .await
            .context(EncodeRequestTypeSnafu)?;
        self.writer
            .encode_one(SshBool(false))
            .await
            .context(EncodeWantReplySnafu)?;
        notice
            .payload()
            .clone()
            .encode_into(&mut self.writer)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut self.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Borrow the underlying writer.
    pub fn inner(&self) -> &W {
        &self.writer
    }

    /// Mutably borrow the underlying writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Consume the wrapper and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

// ===========================================================================
// SshChannelReader — typed wrapper for channel read operations
// ===========================================================================

/// Typed wrapper around a channel's read half for SSH message IO.
///
/// Constructed via [`new`](Self::new) after channel establishment is complete.
/// Provides [`next_event`](Self::next_event) for reading SSH channel events.
/// Only meaningful for channel types that use SSH message framing (e.g.
/// `"session"`). Forwarding channels should use raw streams directly.
pub struct SshChannelReader<R> {
    reader: R,
}

impl<R: AsyncRead + Unpin + Send> SshChannelReader<R> {
    /// Wrap a reader for SSH channel message IO.
    ///
    /// The channel must already be established (open/accept handshake done).
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Read the next event from the channel stream.
    pub async fn next_event(&mut self) -> Result<ChannelEvent<'_, R>, ReadChannelEventError> {
        use read_channel_event_error::*;

        let msg_type: VarInt = self
            .reader
            .decode_one()
            .await
            .context(DecodeMessageTypeSnafu)?;

        match msg_type {
            SSH_MSG_CHANNEL_DATA => {
                let data: SshBytes = self
                    .reader
                    .decode_one()
                    .await
                    .context(DecodeDataSnafu)?;
                Ok(ChannelEvent::Data(data))
            }
            SSH_MSG_CHANNEL_EXTENDED_DATA => {
                let data_type: VarInt = self
                    .reader
                    .decode_one()
                    .await
                    .context(DecodeExtendedDataTypeSnafu)?;
                let data: SshBytes = self
                    .reader
                    .decode_one()
                    .await
                    .context(DecodeExtendedDataSnafu)?;
                Ok(ChannelEvent::ExtendedData { data_type, data })
            }
            SSH_MSG_CHANNEL_REQUEST => {
                let request_type: SshString = self
                    .reader
                    .decode_one()
                    .await
                    .context(DecodeRequestTypeSnafu)?;
                let want_reply: SshBool = self
                    .reader
                    .decode_one()
                    .await
                    .context(DecodeWantReplySnafu)?;
                Ok(ChannelEvent::Request(IncomingChannelRequest {
                    request_type,
                    want_reply: want_reply.0,
                    reader: &mut self.reader,
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

    /// Borrow the underlying reader.
    pub fn inner(&self) -> &R {
        &self.reader
    }

    /// Mutably borrow the underlying reader.
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the wrapper and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

// ===========================================================================
// Channel event types
// ===========================================================================

/// An event read from a channel stream.
///
/// Returned by [`SshChannelReader::next_event`]. For `Request` events, the
/// caller inspects the request type and then decodes the payload via
/// [`IncomingChannelRequest`].
pub enum ChannelEvent<'r, R> {
    /// Channel data (`SSH_MSG_CHANNEL_DATA`).
    Data(SshBytes),
    /// Extended channel data (`SSH_MSG_CHANNEL_EXTENDED_DATA`).
    ExtendedData { data_type: VarInt, data: SshBytes },
    /// A channel request with deferred payload decode.
    Request(IncomingChannelRequest<'r, R>),
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
// IncomingChannelRequest — deferred payload decode
// ---------------------------------------------------------------------------

/// An incoming channel request with deferred payload decoding.
///
/// The header (request type and want_reply flag) has been read; the payload
/// remains on the stream. Call [`decode_payload`](Self::decode_payload) to
/// decode it.
///
/// Unlike global requests, channel streams are independent — dropping this
/// struct does **not** poison the session. However, the stream will contain
/// residual bytes that make further reads nonsensical, so the caller should
/// close or abandon the channel.
pub struct IncomingChannelRequest<'r, R> {
    request_type: SshString,
    want_reply: bool,
    reader: &'r mut R,
}

impl<'r, R> IncomingChannelRequest<'r, R>
where
    R: AsyncRead + Unpin + Send,
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
    /// [`ChannelResponder`] that must be used to send the reply (the writer
    /// is passed later when calling [`respond_success`](ChannelResponder::respond_success)
    /// or [`respond_failure`](ChannelResponder::respond_failure)). If
    /// `want_reply` is false, returns `None`.
    pub async fn decode_payload<T, DE>(
        self,
    ) -> Result<(T, Option<ChannelResponder>), DE>
    where
        T: DecodeFrom<&'r mut R, Error = DE>,
    {
        let value = T::decode_from(self.reader).await?;
        let responder = if self.want_reply {
            Some(ChannelResponder { _private: () })
        } else {
            None
        };
        Ok((value, responder))
    }
}

// ---------------------------------------------------------------------------
// ChannelResponder — send success/failure for a channel request
// ---------------------------------------------------------------------------

/// A responder for an incoming channel request that expects a reply.
///
/// Obtained from [`IncomingChannelRequest::decode_payload`] when
/// `want_reply` is true. Use [`respond_success`](Self::respond_success) or
/// [`respond_failure`](Self::respond_failure) to send the reply, passing
/// the channel writer at that point.
///
/// Dropping without responding is silent (the remote will time out or
/// interpret the absence as failure, depending on implementation). This does
/// **not** poison the session — channels are independent.
pub struct ChannelResponder {
    _private: (),
}

impl ChannelResponder {
    /// Send a success response, optionally with a payload.
    pub async fn respond_success<W, P, RE>(
        self,
        writer: &mut SshChannelWriter<W>,
        response: P,
    ) -> Result<(), RespondChannelSuccessError<RE>>
    where
        W: AsyncWrite + Unpin + Send,
        RE: std::error::Error + Send + Sync + 'static,
        for<'a> P: EncodeInto<&'a mut W, Output = (), Error = RE>,
    {
        use respond_channel_success_error::*;

        writer
            .writer
            .encode_one(SSH_MSG_CHANNEL_SUCCESS)
            .await
            .context(EncodeMessageTypeSnafu)?;
        response
            .encode_into(&mut writer.writer)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut writer.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }

    /// Send a failure response.
    pub async fn respond_failure<W>(
        self,
        writer: &mut SshChannelWriter<W>,
    ) -> Result<(), RespondChannelFailureError>
    where
        W: AsyncWrite + Unpin + Send,
    {
        use respond_channel_failure_error::*;

        writer
            .writer
            .encode_one(SSH_MSG_CHANNEL_FAILURE)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(&mut writer.writer)
            .await
            .context(FlushSnafu)?;
        Ok(())
    }
}
