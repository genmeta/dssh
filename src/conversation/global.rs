use std::sync::Arc;

use h3x::{
    codec::{DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::codec::{CodecError, SshString};

use super::{
    ConversationShared, OrderedGuard, SSH_MSG_REQUEST_FAILURE,
    SSH_MSG_REQUEST_SUCCESS,
};

// ===========================================================================
// Error types
// ===========================================================================

/// Error returned when an operation is attempted on a poisoned session.
#[derive(Debug, Snafu)]
#[snafu(display("session has been poisoned due to unrecoverable IO state"))]
pub struct SessionPoisonedError;

/// Error from [`super::Conversation::request`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::conversation)))]
pub enum SendRequestError<
    PE: std::error::Error + Send + Sync + 'static,
    SE: std::error::Error + Send + Sync + 'static,
> {
    #[snafu(display("failed to encode request message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode request type string"))]
    EncodeRequestType { source: CodecError },
    #[snafu(display("failed to encode want_reply flag"))]
    EncodeWantReply { source: CodecError },
    #[snafu(display("failed to encode request payload"))]
    EncodePayload { source: PE },
    #[snafu(display("failed to flush control stream after request"))]
    Flush { source: std::io::Error },
    #[snafu(display("failed to decode response message type"))]
    DecodeResponseType { source: std::io::Error },
    #[snafu(display("failed to decode success response"))]
    DecodeSuccess { source: SE },
    #[snafu(display("global request was rejected by remote"))]
    Rejected,
    #[snafu(display("unexpected response message type {message_type}"))]
    UnexpectedResponseType { message_type: VarInt },
    #[snafu(display("session has been poisoned"))]
    SessionPoisoned,
}

/// Error from [`super::Conversation::notify`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::conversation)))]
pub enum SendNotifyError<PE: std::error::Error + Send + Sync + 'static> {
    #[snafu(display("failed to encode notify message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode notify type string"))]
    EncodeRequestType { source: CodecError },
    #[snafu(display("failed to encode want_reply flag"))]
    EncodeWantReply { source: CodecError },
    #[snafu(display("failed to encode notify payload"))]
    EncodePayload { source: PE },
    #[snafu(display("failed to flush control stream after notify"))]
    Flush { source: std::io::Error },
    #[snafu(display("session has been poisoned"))]
    SessionPoisoned,
}

/// Error from [`super::Conversation::accept`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::conversation)))]
pub enum AcceptError {
    #[snafu(display("failed to decode incoming message type"))]
    DecodeMessageType { source: std::io::Error },
    #[snafu(display("failed to decode incoming request type string"))]
    DecodeRequestType { source: CodecError },
    #[snafu(display("failed to decode incoming want_reply flag"))]
    DecodeWantReply { source: CodecError },
    #[snafu(display("unexpected message type {message_type} on control stream"))]
    UnexpectedMessageType { message_type: VarInt },
    #[snafu(display("session has been poisoned"))]
    SessionPoisoned,
}

/// Error from [`DecodedGlobalRequest::respond_success`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RespondSuccessError<RE: std::error::Error + Send + Sync + 'static> {
    #[snafu(display("failed to encode success message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to encode success response payload"))]
    EncodePayload { source: RE },
    #[snafu(display("failed to flush control stream after response"))]
    Flush { source: std::io::Error },
    #[snafu(display("session has been poisoned"))]
    SessionPoisoned,
}

/// Error from [`DecodedGlobalRequest::respond_failure`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RespondFailureError {
    #[snafu(display("failed to encode failure message type"))]
    EncodeMessageType { source: std::io::Error },
    #[snafu(display("failed to flush control stream after failure"))]
    Flush { source: std::io::Error },
    #[snafu(display("session has been poisoned"))]
    SessionPoisoned,
}

// ===========================================================================
// IncomingGlobal
// ===========================================================================

pub enum IncomingGlobal<R, W> {
    Notify(IncomingGlobalNotice<R, W>),
    Request(IncomingGlobalRequest<R, W>),
}

// ---------------------------------------------------------------------------
// IncomingGlobalRequest (want_reply = true)
// ---------------------------------------------------------------------------

/// An incoming global request that expects a reply.
///
/// Call [`decode_payload`](Self::decode_payload) to decode the request body
/// and obtain a [`DecodedGlobalRequest`] that can be used to send a response.
///
/// Dropping without decoding poisons the session (the stream contains
/// residual unknown bytes that cannot be skipped).
#[must_use = "incoming global requests must be decoded and answered"]
pub struct IncomingGlobalRequest<R, W> {
    request_type: SshString,
    reader_guard: Option<OrderedGuard<R>>,
    writer_ticket: Option<u64>,
    shared: Arc<ConversationShared<R, W>>,
}

impl<R, W> IncomingGlobalRequest<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    pub(super) fn new(
        request_type: SshString,
        reader_guard: OrderedGuard<R>,
        writer_ticket: u64,
        shared: Arc<ConversationShared<R, W>>,
    ) -> Self {
        Self {
            request_type,
            reader_guard: Some(reader_guard),
            writer_ticket: Some(writer_ticket),
            shared,
        }
    }

    /// The SSH request type string sent by the remote.
    pub fn request_type(&self) -> &SshString {
        &self.request_type
    }

    /// Decode the request payload directly from the control stream.
    ///
    /// Consumes `self` and returns the decoded value together with a
    /// [`DecodedGlobalRequest`] that must be used to send the reply.
    ///
    /// On decode failure the stream is irrecoverably corrupted (partial
    /// bytes consumed), so the session is poisoned when `self` drops.
    pub async fn decode_payload<T, DE>(mut self) -> Result<(T, DecodedGlobalRequest<R, W>), DE>
    where
        T: for<'r> DecodeFrom<&'r mut R, Error = DE>,
    {
        let guard = self.reader_guard.as_mut().expect("reader_guard missing");

        let result = T::decode_from(&mut **guard).await;

        match result {
            Ok(value) => {
                // Release the reader guard so the next message can be read.
                self.reader_guard = None;
                // Move the writer ticket into DecodedGlobalRequest.
                let ticket = self.writer_ticket.take();
                let decoded = DecodedGlobalRequest {
                    writer_ticket: ticket,
                    shared: Arc::clone(&self.shared),
                };
                // self drops here: reader_guard=None → no poison,
                // writer_ticket=None → no auto-failure.
                Ok((value, decoded))
            }
            Err(e) => {
                // self drops here: reader_guard=Some → poison.
                Err(e)
            }
        }
    }
}

impl<R, W> Drop for IncomingGlobalRequest<R, W> {
    fn drop(&mut self) {
        if self.reader_guard.is_some() {
            // Stream has residual unknown bytes — unrecoverable.
            self.shared.poison();
        }
        // writer_ticket is only Some if decode was never called (reader_guard
        // is also Some in that case, handled above). After successful decode
        // it has been moved to DecodedGlobalRequest.
    }
}

// ---------------------------------------------------------------------------
// DecodedGlobalRequest (decoded, awaiting response)
// ---------------------------------------------------------------------------

/// A decoded incoming global request awaiting a response.
///
/// Obtained from [`IncomingGlobalRequest::decode_payload`]. Use
/// [`respond_success`](Self::respond_success) or
/// [`respond_failure`](Self::respond_failure) to send the reply.
///
/// Dropping without responding queues an automatic failure response.
#[must_use = "decoded global requests should be answered"]
pub struct DecodedGlobalRequest<R, W> {
    writer_ticket: Option<u64>,
    shared: Arc<ConversationShared<R, W>>,
}

impl<R, W> DecodedGlobalRequest<R, W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Send a success response with the given payload.
    ///
    /// Waits for the writer ticket to be served (ensuring response ordering).
    /// Consumes `self`.
    pub async fn respond_success<RS, RE>(
        mut self,
        response: RS,
    ) -> Result<(), RespondSuccessError<RE>>
    where
        RE: std::error::Error + Send + Sync + 'static,
        for<'w> RS: EncodeInto<&'w mut W, Output = (), Error = RE>,
    {
        use respond_success_error::*;

        let ticket = self
            .writer_ticket
            .take()
            .expect("writer ticket already consumed");

        let mut guard = self
            .shared
            .acquire_writer(ticket)
            .await
            .map_err(|_| RespondSuccessError::SessionPoisoned)?;

        let _poison_on_drop = PoisonOnDrop(&self.shared);

        (*guard)
            .encode_one(SSH_MSG_REQUEST_SUCCESS)
            .await
            .context(EncodeMessageTypeSnafu)?;
        response
            .encode_into(&mut *guard)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut *guard)
            .await
            .context(FlushSnafu)?;

        std::mem::forget(_poison_on_drop);
        Ok(())
    }

    /// Send a failure response. Waits for the writer ticket to be served.
    /// Consumes `self`.
    pub async fn respond_failure(mut self) -> Result<(), RespondFailureError> {
        use respond_failure_error::*;

        let ticket = self
            .writer_ticket
            .take()
            .expect("writer ticket already consumed");

        let mut guard = self
            .shared
            .acquire_writer(ticket)
            .await
            .map_err(|_| RespondFailureError::SessionPoisoned)?;

        let _poison = PoisonOnDrop(&self.shared);

        (*guard)
            .encode_one(SSH_MSG_REQUEST_FAILURE)
            .await
            .context(EncodeMessageTypeSnafu)?;
        AsyncWriteExt::flush(&mut *guard)
            .await
            .context(FlushSnafu)?;

        std::mem::forget(_poison);
        Ok(())
    }
}

impl<R, W> Drop for DecodedGlobalRequest<R, W> {
    fn drop(&mut self) {
        if let Some(ticket) = self.writer_ticket.take() {
            self.shared.auto_failures.lock().unwrap().insert(ticket);
            self.shared.writer.notify_waiters();
        }
    }
}

// ---------------------------------------------------------------------------
// IncomingGlobalNotice (want_reply = false)
// ---------------------------------------------------------------------------

/// An incoming global notification (no reply expected).
///
/// Call [`decode_payload`](Self::decode_payload) to decode the notification
/// body. Dropping without decoding poisons the session.
#[must_use = "incoming global notices must be decoded"]
pub struct IncomingGlobalNotice<R, W> {
    request_type: SshString,
    reader_guard: Option<OrderedGuard<R>>,
    shared: Arc<ConversationShared<R, W>>,
}

impl<R, W> IncomingGlobalNotice<R, W>
where
    R: AsyncRead + Unpin + Send,
{
    pub(super) fn new(
        request_type: SshString,
        reader_guard: OrderedGuard<R>,
        shared: Arc<ConversationShared<R, W>>,
    ) -> Self {
        Self {
            request_type,
            reader_guard: Some(reader_guard),
            shared,
        }
    }

    /// The SSH request type string sent by the remote.
    pub fn request_type(&self) -> &SshString {
        &self.request_type
    }

    /// Decode the notification payload directly from the control stream.
    ///
    /// Consumes `self`. On decode failure the session is poisoned (partial
    /// bytes consumed make the stream irrecoverable).
    pub async fn decode_payload<T, DE>(mut self) -> Result<T, DE>
    where
        T: for<'r> DecodeFrom<&'r mut R, Error = DE>,
    {
        let guard = self.reader_guard.as_mut().expect("reader_guard missing");

        let result = T::decode_from(&mut **guard).await;

        if result.is_ok() {
            self.reader_guard = None;
        }
        // On error, self drops with reader_guard=Some → poison.

        result
    }
}

impl<R, W> Drop for IncomingGlobalNotice<R, W> {
    fn drop(&mut self) {
        if self.reader_guard.is_some() {
            self.shared.poison();
        }
    }
}

// ---------------------------------------------------------------------------
// PoisonOnDrop — marks session poisoned if dropped before disarming
// ---------------------------------------------------------------------------

pub(super) struct PoisonOnDrop<'a, R, W>(pub(super) &'a ConversationShared<R, W>);

impl<R, W> Drop for PoisonOnDrop<'_, R, W> {
    fn drop(&mut self) {
        self.0.poison();
    }
}
