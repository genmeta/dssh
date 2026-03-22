//! SSH3 conversation (session) abstraction.
//!
//! A *conversation* is the SSH3 equivalent of an SSH2 session — it manages
//! channels and global requests over a QUIC CONNECT stream.
//!
//! # Design
//!
//! The conversation provides concurrent-safe global request handling via an
//! ordered ticket mechanism. All public methods take `&self` (not `&mut self`),
//! allowing global request processing and channel operations to proceed in
//! parallel.
//!
//! ## Global request traits
//!
//! Instead of enumerating all known request types, global requests are
//! abstracted as traits ([`WantReplyGlobalRequest`] and
//! [`NotifyGlobalRequest`]). Encoding and decoding happen directly on the
//! underlying stream with no intermediate structures.
//!
//! ## Ordered IO access
//!
//! SSH global request-response pairs are associated by order. The conversation
//! uses an internal ticket-based mechanism to ensure:
//!
//! - Outgoing requests are sent in allocation order.
//! - Responses to outgoing requests are read in the same order.
//! - Responses to incoming requests are sent in the order the requests arrived.
//!
//! ## Incoming request lifecycle
//!
//! [`IncomingGlobalRequest`] progresses through phases:
//!
//! 1. **Created** — holds a reader guard; caller inspects `request_type()`.
//! 2. **Decoded** — `decode_payload()` decodes the payload on the stream and
//!    releases the reader guard so the next message can be read.
//! 3. **Responded** — `respond_success()` or `respond_failure()` sends the
//!    reply (waiting for its turn on the writer).
//!
//! Dropping at the wrong phase poisons or auto-rejects:
//!
//! - Drop while reader guard held → **session poisoned** (stream has unknown
//!   residual bytes).
//! - Drop after decode but before respond (want_reply) → automatic failure
//!   response is queued.

use std::cell::UnsafeCell;
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    quic::{self, GetStreamIdExt, ReadStream, WriteStream},
    stream_id::StreamId,
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;

use crate::codec::{CodecError, SshBool, SshString};

const SSH_MSG_GLOBAL_REQUEST: VarInt = VarInt::from_u32(80);
const SSH_MSG_REQUEST_SUCCESS: VarInt = VarInt::from_u32(81);
const SSH_MSG_REQUEST_FAILURE: VarInt = VarInt::from_u32(82);

// ===========================================================================
// Error types
// ===========================================================================

/// Error returned when an operation is attempted on a poisoned session.
#[derive(Debug, Snafu)]
#[snafu(display("session has been poisoned due to unrecoverable IO state"))]
pub struct SessionPoisonedError;

/// Error from [`Conversation::request`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SendRequestError<PE: std::error::Error + Send + Sync + 'static, SE: std::error::Error + Send + Sync + 'static> {
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

/// Error from [`Conversation::notify`].
#[derive(Debug, Snafu)]
#[snafu(module)]
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

/// Error from [`Conversation::accept`].
#[derive(Debug, Snafu)]
#[snafu(module)]
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
// Ordered access mechanism
// ===========================================================================

struct OrderedAccessInner<T> {
    resource: UnsafeCell<T>,
    next_ticket: AtomicU64,
    current_serving: AtomicU64,
    notify: Notify,
}

// SAFETY: Access to `resource` is serialized by the ticket mechanism.
// Only the task whose ticket matches `current_serving` may access the
// resource, providing the mutual exclusion required by UnsafeCell.
unsafe impl<T: Send> Send for OrderedAccessInner<T> {}
unsafe impl<T: Send> Sync for OrderedAccessInner<T> {}

struct OrderedAccess<T> {
    inner: Arc<OrderedAccessInner<T>>,
}

impl<T> OrderedAccess<T> {
    fn new(resource: T) -> Self {
        Self {
            inner: Arc::new(OrderedAccessInner {
                resource: UnsafeCell::new(resource),
                next_ticket: AtomicU64::new(0),
                current_serving: AtomicU64::new(0),
                notify: Notify::new(),
            }),
        }
    }

    fn take_ticket(&self) -> u64 {
        self.inner.next_ticket.fetch_add(1, Ordering::SeqCst)
    }

    fn current_serving(&self) -> u64 {
        self.inner.current_serving.load(Ordering::SeqCst)
    }

    async fn acquire(
        &self,
        ticket: u64,
        poisoned: &AtomicBool,
    ) -> Result<OrderedGuard<T>, SessionPoisonedError> {
        loop {
            let mut notified = pin!(self.inner.notify.notified());
            notified.as_mut().enable();

            if poisoned.load(Ordering::SeqCst) {
                return Err(SessionPoisonedError);
            }
            if self.inner.current_serving.load(Ordering::SeqCst) == ticket {
                return Ok(OrderedGuard {
                    inner: Arc::clone(&self.inner),
                });
            }
            notified.await;
        }
    }

    fn notify_waiters(&self) {
        self.inner.notify.notify_waiters();
    }
}

/// RAII guard that provides exclusive mutable access to the ordered resource.
/// On drop, advances `current_serving` and wakes the next waiter.
struct OrderedGuard<T> {
    inner: Arc<OrderedAccessInner<T>>,
}

impl<T> std::ops::Deref for OrderedGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: ticket mechanism guarantees exclusive access.
        unsafe { &*self.inner.resource.get() }
    }
}

impl<T> std::ops::DerefMut for OrderedGuard<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: ticket mechanism guarantees exclusive access.
        unsafe { &mut *self.inner.resource.get() }
    }
}

impl<T> Drop for OrderedGuard<T> {
    fn drop(&mut self) {
        self.inner.current_serving.fetch_add(1, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }
}

// ===========================================================================
// Global request traits
// ===========================================================================

/// A global request that expects a reply (`want_reply = true`).
///
/// Implementors define the payload and success response types. Encoding and
/// decoding bounds are checked at the call site against the concrete stream
/// types from [`ManageSessionStream`].
pub trait WantReplyGlobalRequest {
    /// Successful response type, decoded directly from the stream.
    type Success;

    /// Payload type, encoded directly onto the stream.
    type Payload: Clone;

    /// The SSH request type string (e.g. `"tcpip-forward"`).
    fn request_type(&self) -> SshString;

    /// Reference to the payload.
    fn payload(&self) -> &Self::Payload;
}

/// A global request that does not expect a reply (`want_reply = false`).
pub trait NotifyGlobalRequest {
    /// Payload type, encoded directly onto the stream.
    type Payload: Clone;

    /// The SSH request type string.
    fn request_type(&self) -> SshString;

    /// Reference to the payload.
    fn payload(&self) -> &Self::Payload;
}

// ===========================================================================
// ManageSessionStream trait
// ===========================================================================

pub trait ManageSessionStream {
    type StreamReader: AsyncRead + ReadStream + Unpin;
    type StreamWriter: AsyncWrite + WriteStream + Unpin;
    type Error;

    fn open_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::Error>> + Send;

    fn accept_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::Error>> + Send;
}

mod chmoc {
    use h3x::{
        codec::{SinkWriter, StreamReader},
        dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
        quic,
        remoc::quic::{ReadStreamClient, WriteStreamClient},
    };

    #[remoc::rtc::remote]
    trait ManageSessionStream {
        async fn open_stream(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;

        async fn accept_stream(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;
    }

    impl super::ManageSessionStream for ManageSessionStreamClient {
        type StreamReader = StreamReader<BoxDynQuicStreamReader>;

        type StreamWriter = SinkWriter<BoxDynQuicStreamWriter>;

        type Error = quic::ConnectionError;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            ManageSessionStream::open_stream(self).await.map(|(r, w)| {
                let r = StreamReader::new(r.into_boxed_quic());
                let w = SinkWriter::new(w.into_boxed_quic());
                (r, w)
            })
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            ManageSessionStream::accept_stream(self)
                .await
                .map(|(r, w)| {
                    let r = StreamReader::new(r.into_boxed_quic());
                    let w = SinkWriter::new(w.into_boxed_quic());
                    (r, w)
                })
        }
    }
}

// ===========================================================================
// Conversation shared state
// ===========================================================================

struct ConversationShared<M: ManageSessionStream> {
    reader: OrderedAccess<M::StreamReader>,
    writer: OrderedAccess<M::StreamWriter>,
    poisoned: AtomicBool,
    /// Lock to atomically allocate paired (writer, reader) tickets for
    /// outgoing requests, ensuring send order matches receive order.
    ticket_pair_lock: std::sync::Mutex<()>,
    /// Writer tickets that should automatically send a failure response.
    /// Populated when an [`IncomingGlobalRequest`] is dropped after decoding
    /// but before responding.
    auto_failures: std::sync::Mutex<BTreeSet<u64>>,
}

impl<M: ManageSessionStream> ConversationShared<M> {
    fn poison(&self) {
        self.poisoned.store(true, Ordering::SeqCst);
        self.reader.notify_waiters();
        self.writer.notify_waiters();
    }

    /// Atomically allocate a writer ticket and a reader ticket, ensuring the
    /// pairing order is consistent across concurrent callers.
    fn allocate_request_ticket_pair(&self) -> (u64, u64) {
        let _lock = self.ticket_pair_lock.lock().unwrap();
        let write_ticket = self.writer.take_ticket();
        let read_ticket = self.reader.take_ticket();
        (write_ticket, read_ticket)
    }

    /// Drain any consecutive auto-failure responses starting from the current
    /// writer serving position. Called before a real writer tries to acquire.
    async fn drain_auto_failures(&self) -> Result<(), SessionPoisonedError> {
        loop {
            let current = self.writer.current_serving();
            let should_drain = self.auto_failures.lock().unwrap().remove(&current);
            if !should_drain {
                break;
            }

            let mut guard = self.writer.acquire(current, &self.poisoned).await?;

            // Encode SSH_MSG_REQUEST_FAILURE directly on the stream.
            let encode_result = (*guard).encode_one(SSH_MSG_REQUEST_FAILURE).await;
            let flush_result = if encode_result.is_ok() {
                AsyncWriteExt::flush(&mut *guard).await
            } else {
                Ok(())
            };

            drop(guard);

            if encode_result.is_err() || flush_result.is_err() {
                self.poison();
                return Err(SessionPoisonedError);
            }
        }
        Ok(())
    }

    /// Acquire the writer for the given ticket, draining any preceding
    /// auto-failure responses first.
    async fn acquire_writer(
        &self,
        ticket: u64,
    ) -> Result<OrderedGuard<M::StreamWriter>, SessionPoisonedError> {
        loop {
            self.drain_auto_failures().await?;

            if self.writer.current_serving() == ticket {
                return self.writer.acquire(ticket, &self.poisoned).await;
            }

            // Not our turn yet — wait for a notification and retry.
            let mut notified = pin!(self.writer.inner.notify.notified());
            notified.as_mut().enable();
            if self.poisoned.load(Ordering::SeqCst) {
                return Err(SessionPoisonedError);
            }
            if self.writer.current_serving() == ticket {
                return self.writer.acquire(ticket, &self.poisoned).await;
            }
            notified.await;
        }
    }
}

// ===========================================================================
// Conversation
// ===========================================================================

pub struct Conversation<M: ManageSessionStream> {
    id: StreamId,
    shared: Arc<ConversationShared<M>>,
    _manage_stream: M,
}

impl<M: ManageSessionStream> Conversation<M> {
    pub async fn new(
        mut control_stream_reader: M::StreamReader,
        control_stream_writer: M::StreamWriter,
        manage_stream: M,
    ) -> Result<Self, quic::StreamError> {
        Ok(Self {
            id: StreamId(control_stream_reader.stream_id().await?),
            shared: Arc::new(ConversationShared {
                reader: OrderedAccess::new(control_stream_reader),
                writer: OrderedAccess::new(control_stream_writer),
                poisoned: AtomicBool::new(false),
                ticket_pair_lock: std::sync::Mutex::new(()),
                auto_failures: std::sync::Mutex::new(BTreeSet::new()),
            }),
            _manage_stream: manage_stream,
        })
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Send a global request that expects a reply and wait for the response.
    ///
    /// Multiple concurrent calls are safe; the ticket mechanism ensures
    /// requests are sent and responses are read in a consistent order.
    ///
    /// `PE` and `SE` are the encode/decode error types of the payload and
    /// success response respectively. They are inferred from the trait bounds.
    pub async fn request<R, PE, SE>(
        &self,
        request: &R,
    ) -> Result<R::Success, SendRequestError<PE, SE>>
    where
        R: WantReplyGlobalRequest,
        PE: std::error::Error + Send + Sync + 'static,
        SE: std::error::Error + Send + Sync + 'static,
        for<'w> R::Payload: EncodeInto<&'w mut M::StreamWriter, Output = (), Error = PE>,
        for<'r> R::Success: DecodeFrom<&'r mut M::StreamReader, Error = SE>,
    {
        use send_request_error::*;

        let (write_ticket, read_ticket) = self.shared.allocate_request_ticket_pair();

        // --- Send the request ---
        {
            let mut guard = self
                .shared
                .acquire_writer(write_ticket)
                .await
                .map_err(|_| SendRequestError::SessionPoisoned)?;

            // If any encode step fails after partial bytes are written, the
            // stream is corrupted. Poison the session on drop; disarm after
            // the flush succeeds.
            let _poison = PoisonOnDrop(&self.shared);

            (*guard)
                .encode_one(SSH_MSG_GLOBAL_REQUEST)
                .await
                .context(EncodeMessageTypeSnafu)?;
            (*guard)
                .encode_one(request.request_type())
                .await
                .context(EncodeRequestTypeSnafu)?;
            (*guard)
                .encode_one(SshBool(true))
                .await
                .context(EncodeWantReplySnafu)?;
            request
                .payload()
                .clone()
                .encode_into(&mut *guard)
                .await
                .context(EncodePayloadSnafu)?;
            AsyncWriteExt::flush(&mut *guard)
                .await
                .context(FlushSnafu)?;

            std::mem::forget(_poison);
        }

        // --- Read the response ---
        {
            let mut guard = self
                .shared
                .reader
                .acquire(read_ticket, &self.shared.poisoned)
                .await
                .map_err(|_| SendRequestError::SessionPoisoned)?;

            let msg_type: VarInt = (*guard)
                .decode_one()
                .await
                .context(DecodeResponseTypeSnafu)?;

            match msg_type {
                SSH_MSG_REQUEST_SUCCESS => {
                    let success = R::Success::decode_from(&mut *guard)
                        .await
                        .context(DecodeSuccessSnafu)?;
                    Ok(success)
                }
                SSH_MSG_REQUEST_FAILURE => Err(SendRequestError::Rejected),
                other => Err(SendRequestError::UnexpectedResponseType {
                    message_type: other,
                }),
            }
        }
    }

    /// Send a global notification (no reply expected).
    pub async fn notify<N, PE>(
        &self,
        notice: &N,
    ) -> Result<(), SendNotifyError<PE>>
    where
        N: NotifyGlobalRequest,
        PE: std::error::Error + Send + Sync + 'static,
        for<'w> N::Payload: EncodeInto<&'w mut M::StreamWriter, Output = (), Error = PE>,
    {
        use send_notify_error::*;

        let write_ticket = self.shared.writer.take_ticket();

        let mut guard = self
            .shared
            .acquire_writer(write_ticket)
            .await
            .map_err(|_| SendNotifyError::SessionPoisoned)?;

        let _poison = PoisonOnDrop(&self.shared);

        (*guard)
            .encode_one(SSH_MSG_GLOBAL_REQUEST)
            .await
            .context(EncodeMessageTypeSnafu)?;
        (*guard)
            .encode_one(notice.request_type())
            .await
            .context(EncodeRequestTypeSnafu)?;
        (*guard)
            .encode_one(SshBool(false))
            .await
            .context(EncodeWantReplySnafu)?;
        notice
            .payload()
            .clone()
            .encode_into(&mut *guard)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut *guard)
            .await
            .context(FlushSnafu)?;

        std::mem::forget(_poison);

        Ok(())
    }

    /// Read the next incoming global request or notification from the control
    /// stream.
    ///
    /// Returns an [`IncomingGlobal`] that holds a reader guard for the caller
    /// to decode the payload. The reader guard **must** be released (via
    /// [`IncomingGlobalRequest::decode_payload`] or
    /// [`IncomingGlobalNotice::decode_payload`]) before the next `accept()`
    /// can proceed.
    pub async fn accept(&self) -> Result<IncomingGlobal<M>, AcceptError> {
        use accept_error::*;

        let read_ticket = self.shared.reader.take_ticket();

        let mut guard = self
            .shared
            .reader
            .acquire(read_ticket, &self.shared.poisoned)
            .await
            .map_err(|_| AcceptError::SessionPoisoned)?;

        // If any decode step fails after partial bytes are consumed, or if we
        // encounter an unexpected message type whose body length is unknown,
        // the stream is corrupted. Poison the session on drop; disarm on the
        // success path when the guard is transferred to IncomingGlobal*.
        let poison = PoisonOnDrop(&self.shared);

        let msg_type: VarInt = (*guard)
            .decode_one()
            .await
            .context(DecodeMessageTypeSnafu)?;

        if msg_type != SSH_MSG_GLOBAL_REQUEST {
            // Unknown message body remains on the stream — poison (via drop).
            return Err(AcceptError::UnexpectedMessageType {
                message_type: msg_type,
            });
        }

        let request_type: SshString = (*guard)
            .decode_one()
            .await
            .context(DecodeRequestTypeSnafu)?;
        let want_reply: SshBool = (*guard)
            .decode_one()
            .await
            .context(DecodeWantReplySnafu)?;

        // Header fully decoded — disarm the poison guard. From here, the
        // reader guard moves into IncomingGlobal* whose own Drop handles
        // the remaining payload lifecycle.
        std::mem::forget(poison);

        if want_reply.0 {
            let write_ticket = self.shared.writer.take_ticket();
            Ok(IncomingGlobal::Request(IncomingGlobalRequest {
                request_type,
                reader_guard: Some(guard),
                writer_ticket: Some(write_ticket),
                shared: Arc::clone(&self.shared),
            }))
        } else {
            Ok(IncomingGlobal::Notify(IncomingGlobalNotice {
                request_type,
                reader_guard: Some(guard),
                shared: Arc::clone(&self.shared),
            }))
        }
    }
}

// ===========================================================================
// Incoming global messages
// ===========================================================================

pub enum IncomingGlobal<M: ManageSessionStream> {
    Notify(IncomingGlobalNotice<M>),
    Request(IncomingGlobalRequest<M>),
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
pub struct IncomingGlobalRequest<M: ManageSessionStream> {
    request_type: SshString,
    reader_guard: Option<OrderedGuard<M::StreamReader>>,
    writer_ticket: Option<u64>,
    shared: Arc<ConversationShared<M>>,
}

impl<M: ManageSessionStream> IncomingGlobalRequest<M> {
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
    pub async fn decode_payload<T, DE>(
        mut self,
    ) -> Result<(T, DecodedGlobalRequest<M>), DE>
    where
        T: for<'r> DecodeFrom<&'r mut M::StreamReader, Error = DE>,
    {
        let guard = self
            .reader_guard
            .as_mut()
            .expect("reader_guard missing");

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

impl<M: ManageSessionStream> Drop for IncomingGlobalRequest<M> {
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
pub struct DecodedGlobalRequest<M: ManageSessionStream> {
    writer_ticket: Option<u64>,
    shared: Arc<ConversationShared<M>>,
}

impl<M: ManageSessionStream> DecodedGlobalRequest<M> {
    /// Send a success response with the given payload.
    ///
    /// Waits for the writer ticket to be served (ensuring response ordering).
    /// Consumes `self`.
    pub async fn respond_success<R, RE>(
        mut self,
        response: R,
    ) -> Result<(), RespondSuccessError<RE>>
    where
        RE: std::error::Error + Send + Sync + 'static,
        for<'w> R: EncodeInto<&'w mut M::StreamWriter, Output = (), Error = RE>,
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

impl<M: ManageSessionStream> Drop for DecodedGlobalRequest<M> {
    fn drop(&mut self) {
        if let Some(ticket) = self.writer_ticket.take() {
            self.shared
                .auto_failures
                .lock()
                .unwrap()
                .insert(ticket);
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
pub struct IncomingGlobalNotice<M: ManageSessionStream> {
    request_type: SshString,
    reader_guard: Option<OrderedGuard<M::StreamReader>>,
    shared: Arc<ConversationShared<M>>,
}

impl<M: ManageSessionStream> IncomingGlobalNotice<M> {
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
        T: for<'r> DecodeFrom<&'r mut M::StreamReader, Error = DE>,
    {
        let guard = self
            .reader_guard
            .as_mut()
            .expect("reader_guard missing");

        let result = T::decode_from(&mut **guard).await;

        if result.is_ok() {
            self.reader_guard = None;
        }
        // On error, self drops with reader_guard=Some → poison.

        result
    }
}

impl<M: ManageSessionStream> Drop for IncomingGlobalNotice<M> {
    fn drop(&mut self) {
        if self.reader_guard.is_some() {
            self.shared.poison();
        }
    }
}

// ---------------------------------------------------------------------------
// PoisonOnDrop — marks session poisoned if dropped before disarming
// ---------------------------------------------------------------------------

struct PoisonOnDrop<'a, M: ManageSessionStream>(&'a ConversationShared<M>);

impl<M: ManageSessionStream> Drop for PoisonOnDrop<'_, M> {
    fn drop(&mut self) {
        self.0.poison();
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::pin::Pin;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use futures::{Sink, Stream, channel::mpsc};
    use h3x::{
        codec::{SinkWriter, StreamReader as H3xStreamReader},
        quic::{CancelStream, GetStreamId, StopStream, StreamError},
    };

    // -- Mock stream types that implement h3x ReadStream / WriteStream ------

    struct TestQuicReader {
        stream_id: VarInt,
        inner: mpsc::Receiver<Bytes>,
    }

    impl Unpin for TestQuicReader {}

    impl Stream for TestQuicReader {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Pin::new(&mut self.inner).poll_next(cx).map(|opt| opt.map(Ok))
        }
    }

    impl GetStreamId for TestQuicReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for TestQuicReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    struct TestQuicWriter {
        stream_id: VarInt,
        inner: mpsc::Sender<Bytes>,
    }

    impl Unpin for TestQuicWriter {}

    impl Sink<Bytes> for TestQuicWriter {
        type Error = StreamError;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.inner)
                .poll_ready(cx)
                .map_err(|_| StreamError::Reset {
                    code: VarInt::from_u32(0),
                })
        }

        fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            Pin::new(&mut self.inner)
                .start_send(item)
                .map_err(|_| StreamError::Reset {
                    code: VarInt::from_u32(0),
                })
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.inner)
                .poll_flush(cx)
                .map_err(|_| StreamError::Reset {
                    code: VarInt::from_u32(0),
                })
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.inner)
                .poll_close(cx)
                .map_err(|_| StreamError::Reset {
                    code: VarInt::from_u32(0),
                })
        }
    }

    impl GetStreamId for TestQuicWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl CancelStream for TestQuicWriter {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    // -- Concrete types for ManageSessionStream -----------------------------

    type MockReader = H3xStreamReader<TestQuicReader>;
    type MockWriter = SinkWriter<TestQuicWriter>;

    struct TestManageStream;

    impl ManageSessionStream for TestManageStream {
        type StreamReader = MockReader;
        type StreamWriter = MockWriter;
        type Error = std::convert::Infallible;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            unreachable!("not used in global request tests")
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            unreachable!("not used in global request tests")
        }
    }

    /// Create a connected pair of (reader, writer) for one direction.
    fn make_half(stream_id: VarInt) -> (MockReader, MockWriter) {
        let (tx, rx) = mpsc::channel(64);
        let reader = H3xStreamReader::new(TestQuicReader {
            stream_id,
            inner: rx,
        });
        let writer = SinkWriter::new(TestQuicWriter {
            stream_id,
            inner: tx,
        });
        (reader, writer)
    }

    async fn make_conversation() -> (Conversation<TestManageStream>, MockReader, MockWriter) {
        let stream_id = VarInt::from_u32(42);
        // local reads ← remote writes
        let (local_reader, remote_writer) = make_half(stream_id);
        // remote reads ← local writes
        let (remote_reader, local_writer) = make_half(stream_id);

        let conv = Conversation::new(local_reader, local_writer, TestManageStream)
            .await
            .expect("conversation should be created");
        (conv, remote_reader, remote_writer)
    }

    // -- Test request type implementations ----------------------------------

    /// A simple test request: payload is a single SshString, success is a VarInt.
    #[derive(Clone)]
    struct TestPayload(SshString);

    struct TestRequest {
        payload: TestPayload,
    }

    impl WantReplyGlobalRequest for TestRequest {
        type Success = VarInt;
        type Payload = TestPayload;

        fn request_type(&self) -> SshString {
            SshString::from_static("test-request")
        }

        fn payload(&self) -> &Self::Payload {
            &self.payload
        }
    }

    // EncodeInto for TestPayload: encodes the inner SshString
    impl<S: AsyncWrite + Send> EncodeInto<S> for TestPayload {
        type Output = ();
        type Error = crate::codec::CodecError;

        async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
            self.0.encode_into(stream).await
        }
    }

    // -- Test notify type ---------------------------------------------------

    struct TestNotice {
        payload: TestPayload,
    }

    impl NotifyGlobalRequest for TestNotice {
        type Payload = TestPayload;

        fn request_type(&self) -> SshString {
            SshString::from_static("test-notice")
        }

        fn payload(&self) -> &Self::Payload {
            &self.payload
        }
    }

    // -- Helpers for the "remote" side --------------------------------------

    /// Remote sends a global request with want_reply on the writer.
    async fn remote_send_global_request(
        writer: &mut MockWriter,
        request_type: &str,
        want_reply: bool,
        payload: &str,
    ) {
        (*writer)
            .encode_one(VarInt::from_u32(80)) // SSH_MSG_GLOBAL_REQUEST
            .await
            .unwrap();
        (*writer)
            .encode_one(SshString::from(request_type.to_string()))
            .await
            .unwrap();
        (*writer)
            .encode_one(SshBool(want_reply))
            .await
            .unwrap();
        (*writer)
            .encode_one(SshString::from(payload.to_string()))
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut *writer).await.unwrap();
    }

    /// Remote reads a global request header and returns (request_type, want_reply).
    async fn remote_read_global_request_header(
        reader: &mut MockReader,
    ) -> (SshString, bool) {
        let msg_type: VarInt = (*reader).decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(80));
        let request_type: SshString = (*reader).decode_one().await.unwrap();
        let want_reply: SshBool = (*reader).decode_one().await.unwrap();
        (request_type, want_reply.0)
    }

    /// Remote sends SSH_MSG_REQUEST_SUCCESS followed by a VarInt value.
    async fn remote_send_success(writer: &mut MockWriter, value: u32) {
        (*writer)
            .encode_one(VarInt::from_u32(81)) // SSH_MSG_REQUEST_SUCCESS
            .await
            .unwrap();
        (*writer)
            .encode_one(VarInt::from_u32(value))
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut *writer).await.unwrap();
    }

    /// Remote sends SSH_MSG_REQUEST_FAILURE.
    async fn remote_send_failure(writer: &mut MockWriter) {
        (*writer)
            .encode_one(VarInt::from_u32(82)) // SSH_MSG_REQUEST_FAILURE
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut *writer).await.unwrap();
    }

    // =======================================================================
    // Tests
    // =======================================================================

    #[tokio::test]
    async fn conversation_id() {
        let (conv, _remote_reader, _remote_writer) = make_conversation().await;
        assert_eq!(conv.id(), StreamId(VarInt::from_u32(42)));
    }

    // -- request() tests ----------------------------------------------------

    #[tokio::test]
    async fn request_success_roundtrip() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        let handle = tokio::spawn(async move {
            let (req_type, want_reply) =
                remote_read_global_request_header(&mut remote_reader).await;
            assert_eq!(&*req_type, "test-request");
            assert!(want_reply);
            // Read payload
            let payload: SshString = remote_reader.decode_one().await.unwrap();
            assert_eq!(&*payload, "hello");
            // Send success with value 99
            remote_send_success(&mut remote_writer, 99).await;
        });

        let req = TestRequest {
            payload: TestPayload(SshString::from("hello".to_string())),
        };
        let result: VarInt = conv.request(&req).await.unwrap();
        assert_eq!(result, VarInt::from_u32(99));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn request_rejected() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        let handle = tokio::spawn(async move {
            let _ = remote_read_global_request_header(&mut remote_reader).await;
            let _payload: SshString = remote_reader.decode_one().await.unwrap();
            remote_send_failure(&mut remote_writer).await;
        });

        let req = TestRequest {
            payload: TestPayload(SshString::from("hi".to_string())),
        };
        let result: Result<VarInt, _> = conv.request(&req).await;
        assert!(matches!(result, Err(SendRequestError::Rejected)));

        handle.await.unwrap();
    }

    // -- notify() tests -----------------------------------------------------

    #[tokio::test]
    async fn notify_sends_correctly() {
        let (conv, mut remote_reader, _remote_writer) = make_conversation().await;

        let notice = TestNotice {
            payload: TestPayload(SshString::from("world".to_string())),
        };
        conv.notify(&notice).await.unwrap();

        let (req_type, want_reply) =
            remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(&*req_type, "test-notice");
        assert!(!want_reply);
        let payload: SshString = remote_reader.decode_one().await.unwrap();
        assert_eq!(&*payload, "world");
    }

    // -- accept() tests -----------------------------------------------------

    #[tokio::test]
    async fn accept_incoming_request_decode_and_respond_success() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends a want_reply=true request
        remote_send_global_request(&mut remote_writer, "tcpip-forward", true, "bind-addr")
            .await;

        let incoming = conv.accept().await.unwrap();
        let req = match incoming {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        assert_eq!(&**req.request_type(), "tcpip-forward");

        // Decode payload — consumes req, returns DecodedGlobalRequest
        let (payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();
        assert_eq!(&*payload, "bind-addr");

        // Respond with success (VarInt 8080)
        decoded.respond_success(VarInt::from_u32(8080)).await.unwrap();

        // Verify remote receives success
        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(81)); // SSH_MSG_REQUEST_SUCCESS
        let port: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(port, VarInt::from_u32(8080));
    }

    #[tokio::test]
    async fn accept_incoming_request_respond_failure() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "unknown-req", true, "data").await;

        let incoming = conv.accept().await.unwrap();
        let req = match incoming {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();
        decoded.respond_failure().await.unwrap();

        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(82)); // SSH_MSG_REQUEST_FAILURE
    }

    #[tokio::test]
    async fn accept_incoming_notice() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "keepalive", false, "ping").await;

        let incoming = conv.accept().await.unwrap();
        let notice = match incoming {
            IncomingGlobal::Notify(n) => n,
            _ => panic!("expected Notify"),
        };

        assert_eq!(&**notice.request_type(), "keepalive");
        let payload: SshString = notice.decode_payload().await.unwrap();
        assert_eq!(&*payload, "ping");
    }

    // -- Drop / poisoning tests ---------------------------------------------

    #[tokio::test]
    async fn drop_request_before_decode_poisons_session() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "test", true, "data").await;

        let incoming = conv.accept().await.unwrap();
        let req = match incoming {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        // Drop without decoding → poisons session
        drop(req);

        assert!(conv.shared.poisoned.load(Ordering::SeqCst));

        // Subsequent accept should fail with SessionPoisoned
        let result = conv.accept().await;
        assert!(matches!(result, Err(AcceptError::SessionPoisoned)));
    }

    #[tokio::test]
    async fn drop_notice_before_decode_poisons_session() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "test", false, "data").await;

        let incoming = conv.accept().await.unwrap();
        let notice = match incoming {
            IncomingGlobal::Notify(n) => n,
            _ => panic!("expected Notify"),
        };

        drop(notice);
        assert!(conv.shared.poisoned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn drop_request_after_decode_queues_auto_failure() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "test", true, "data").await;

        let incoming = conv.accept().await.unwrap();
        let req = match incoming {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        // Decode payload — returns DecodedGlobalRequest
        let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

        // Drop DecodedGlobalRequest without responding → should queue auto-failure
        drop(decoded);

        // Session should NOT be poisoned
        assert!(!conv.shared.poisoned.load(Ordering::SeqCst));

        // The auto-failure should be queued
        assert!(conv.shared.auto_failures.lock().unwrap().contains(&0));

        // Trigger drain by sending a notify (which acquires the writer)
        let notice = TestNotice {
            payload: TestPayload(SshString::from("after".to_string())),
        };
        conv.notify(&notice).await.unwrap();

        // Remote should first see the auto-failure response, then the notify
        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(82)); // SSH_MSG_REQUEST_FAILURE (auto)

        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(80)); // SSH_MSG_GLOBAL_REQUEST (notify)
    }

    // -- Response ordering tests --------------------------------------------

    #[tokio::test]
    async fn incoming_request_responses_ordered_correctly() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Send two requests from remote
        remote_send_global_request(&mut remote_writer, "req-a", true, "a").await;
        remote_send_global_request(&mut remote_writer, "req-b", true, "b").await;

        // Accept both
        let incoming_a = conv.accept().await.unwrap();
        let req_a = match incoming_a {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };
        let (_, decoded_a): (SshString, _) = req_a.decode_payload().await.unwrap();

        let incoming_b = conv.accept().await.unwrap();
        let req_b = match incoming_b {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };
        let (_, decoded_b): (SshString, _) = req_b.decode_payload().await.unwrap();

        // Respond to B first (out of order) — it should wait for A
        let b_handle = tokio::spawn(async move {
            decoded_b.respond_success(VarInt::from_u32(200)).await.unwrap();
        });

        // Small delay to ensure B starts waiting
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Now respond to A — this should unblock B
        decoded_a.respond_success(VarInt::from_u32(100)).await.unwrap();
        b_handle.await.unwrap();

        // Remote should receive A's response first, then B's
        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(81)); // SUCCESS
        let val: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(val, VarInt::from_u32(100)); // A's response

        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(81)); // SUCCESS
        let val: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(val, VarInt::from_u32(200)); // B's response
    }

    #[tokio::test]
    async fn unexpected_message_type_poisons_session() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends SSH_MSG_REQUEST_SUCCESS (81) instead of GLOBAL_REQUEST
        remote_writer
            .encode_one(VarInt::from_u32(81))
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut remote_writer).await.unwrap();

        let result = conv.accept().await;
        assert!(matches!(result, Err(AcceptError::UnexpectedMessageType { .. })));

        // Session should be poisoned (unknown body on stream)
        assert!(conv.shared.poisoned.load(Ordering::SeqCst));
    }

    // -- Concurrent request ordering ----------------------------------------

    #[tokio::test]
    async fn concurrent_requests_ordered_correctly() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;
        let conv = Arc::new(conv);

        // Spawn two concurrent request tasks. The ticket mechanism must
        // ensure request A is sent before B, and response A is read before B.
        let conv_a = Arc::clone(&conv);
        let handle_a = tokio::spawn(async move {
            conv_a
                .request::<TestRequest, _, _>(&TestRequest {
                    payload: TestPayload(SshString::from_static("alpha")),
                })
                .await
        });

        let conv_b = Arc::clone(&conv);
        let handle_b = tokio::spawn(async move {
            conv_b
                .request::<TestRequest, _, _>(&TestRequest {
                    payload: TestPayload(SshString::from_static("beta")),
                })
                .await
        });

        // Yield to let both tasks run and acquire tickets
        tokio::task::yield_now().await;

        // Remote reads the first request (A)
        let (req_type_a, want_reply_a) =
            remote_read_global_request_header(&mut remote_reader).await;
        assert!(want_reply_a);
        let payload_a: SshString = remote_reader.decode_one().await.unwrap();

        // Remote reads the second request (B)
        let (req_type_b, want_reply_b) =
            remote_read_global_request_header(&mut remote_reader).await;
        assert!(want_reply_b);
        let payload_b: SshString = remote_reader.decode_one().await.unwrap();

        // Both have the same type
        assert_eq!(req_type_a.as_ref() as &[u8], b"test-request");
        assert_eq!(req_type_b.as_ref() as &[u8], b"test-request");

        // The payloads should be in order (A first, B second)
        let a_payload = payload_a.as_ref().to_vec();
        let b_payload = payload_b.as_ref().to_vec();
        assert_ne!(a_payload, b_payload);

        // Send success response for A, then B
        remote_send_success(&mut remote_writer, 100).await;
        remote_send_success(&mut remote_writer, 200).await;

        let result_a = handle_a.await.unwrap();
        let result_b = handle_b.await.unwrap();

        let val_a = result_a.unwrap();
        let val_b = result_b.unwrap();
        assert_eq!(val_a, VarInt::from_u32(100));
        assert_eq!(val_b, VarInt::from_u32(200));
    }

    // -- Writer auto-failure consecutive drain ------------------------------

    #[tokio::test]
    async fn consecutive_auto_failures_drained_by_next_writer() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends 3 requests that all want a reply
        remote_send_global_request(&mut remote_writer, "req-1", true, "d1").await;
        remote_send_global_request(&mut remote_writer, "req-2", true, "d2").await;
        remote_send_global_request(&mut remote_writer, "req-3", true, "d3").await;

        // Accept and decode all three, but DON'T respond — just drop them.
        // This should queue 3 auto-failure writer tickets.
        for _ in 0..3 {
            match conv.accept().await.unwrap() {
                IncomingGlobal::Request(req) => {
                    let (_payload, _decoded): (SshString, _) =
                        req.decode_payload().await.unwrap();
                    // Drop DecodedGlobalRequest without responding → auto-failure queued
                }
                _ => panic!("expected Request"),
            }
        }

        // The auto-failures haven't been sent yet (no writer has tried to
        // acquire). Now send a notify — this acquires a writer ticket and
        // should drain all 3 auto-failures first.
        let notice = TestNotice {
            payload: TestPayload(SshString::from_static("ping")),
        };
        conv.notify::<TestNotice, _>(&notice).await.unwrap();

        // Remote should see: 3x failure, then the notify
        for _ in 0..3 {
            let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
            assert_eq!(msg_type, SSH_MSG_REQUEST_FAILURE);
        }

        // Now the notify message
        let (req_type, want_reply) =
            remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(req_type.as_ref() as &[u8], b"test-notice");
        assert!(!want_reply);
    }

    // -- Session poison blocks all operations -------------------------------

    #[tokio::test]
    async fn poisoned_session_rejects_request() {
        let (conv, _remote_reader, _remote_writer) = make_conversation().await;

        // Manually poison the session
        conv.shared.poison();

        let result = conv
            .request::<TestRequest, _, _>(&TestRequest {
                payload: TestPayload(SshString::from_static("hello")),
            })
            .await;

        assert!(matches!(result, Err(SendRequestError::SessionPoisoned)));
    }

    #[tokio::test]
    async fn poisoned_session_rejects_notify() {
        let (conv, _remote_reader, _remote_writer) = make_conversation().await;

        conv.shared.poison();

        let notice = TestNotice {
            payload: TestPayload(SshString::from_static("hello")),
        };
        let result = conv.notify::<TestNotice, _>(&notice).await;

        assert!(matches!(result, Err(SendNotifyError::SessionPoisoned)));
    }

    #[tokio::test]
    async fn poisoned_session_rejects_accept() {
        let (conv, _remote_reader, _remote_writer) = make_conversation().await;

        conv.shared.poison();

        let result = conv.accept().await;
        assert!(matches!(result, Err(AcceptError::SessionPoisoned)));
    }

    #[tokio::test]
    async fn poisoned_session_rejects_respond_success() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "test", true, "data").await;

        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

        // Now poison the session before responding
        conv.shared.poison();

        let result = decoded.respond_success(VarInt::from_u32(42)).await;
        assert!(matches!(
            result,
            Err(RespondSuccessError::SessionPoisoned)
        ));
    }

    #[tokio::test]
    async fn poisoned_session_rejects_respond_failure() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "test", true, "data").await;

        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

        conv.shared.poison();

        let result = decoded.respond_failure().await;
        assert!(matches!(result, Err(RespondFailureError::SessionPoisoned)));
    }

    // -- respond_success mid-encode drop poisons ----------------------------

    #[tokio::test]
    async fn respond_success_cancelled_poisons_session() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        remote_send_global_request(&mut remote_writer, "test", true, "data").await;

        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

        // Close the remote side so writes fail/block.
        drop(_remote_reader);
        drop(remote_writer);

        let respond_fut = decoded.respond_success(VarInt::from_u32(42));

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            respond_fut,
        )
        .await;

        match result {
            Ok(Ok(())) => {
                // Extremely unlikely but technically possible
            }
            Ok(Err(_)) => {
                assert!(
                    conv.shared.poisoned.load(Ordering::SeqCst),
                    "session should be poisoned after encode error"
                );
            }
            Err(_elapsed) => {
                assert!(
                    conv.shared.poisoned.load(Ordering::SeqCst),
                    "session should be poisoned after mid-encode cancellation"
                );
            }
        }
    }

    // -- Multiple sequential accept() calls ---------------------------------

    #[tokio::test]
    async fn multiple_sequential_accepts() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends 3 requests
        for i in 0..3u32 {
            remote_send_global_request(
                &mut remote_writer,
                &format!("req-{i}"),
                true,
                &format!("data-{i}"),
            )
            .await;
        }

        // Accept, decode, and respond to each one sequentially.
        for i in 0..3u32 {
            let req = match conv.accept().await.unwrap() {
                IncomingGlobal::Request(r) => r,
                _ => panic!("expected Request"),
            };

            let expected_type = format!("req-{i}");
            assert_eq!(req.request_type().as_ref() as &[u8], expected_type.as_bytes());

            let (payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();
            let expected_payload = format!("data-{i}");
            assert_eq!(payload.as_ref() as &[u8], expected_payload.as_bytes());

            decoded.respond_success(VarInt::from_u32(i * 10)).await.unwrap();
        }

        // Remote reads all 3 success responses
        for i in 0..3u32 {
            let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
            assert_eq!(msg_type, SSH_MSG_REQUEST_SUCCESS);
            let val: VarInt = remote_reader.decode_one().await.unwrap();
            assert_eq!(val, VarInt::from_u32(i * 10));
        }
    }

    // -- Interleaved request + notify on writer ----------------------------

    #[tokio::test]
    async fn interleaved_request_and_notify_on_writer() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Send a notify first, then a request. Both go through the writer
        // ticket system and should be ordered correctly.
        let notice = TestNotice {
            payload: TestPayload(SshString::from_static("notice-1")),
        };
        conv.notify::<TestNotice, _>(&notice).await.unwrap();

        // Now send a request
        // Pre-send the response so request() can complete
        remote_send_success(&mut remote_writer, 777).await;

        let result = conv
            .request::<TestRequest, _, _>(&TestRequest {
                payload: TestPayload(SshString::from_static("req-after-notify")),
            })
            .await;
        assert_eq!(result.unwrap(), VarInt::from_u32(777));

        // Remote should see: notify first, then the request
        let (rt_1, wr_1) = remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(rt_1.as_ref() as &[u8], b"test-notice");
        assert!(!wr_1);
        let _payload_1: SshString = remote_reader.decode_one().await.unwrap();

        let (rt_2, wr_2) = remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(rt_2.as_ref() as &[u8], b"test-request");
        assert!(wr_2);
        let _payload_2: SshString = remote_reader.decode_one().await.unwrap();
    }

    // -- Auto-failure at current_serving is immediately drained -------------

    #[tokio::test]
    async fn auto_failure_at_current_serving_drained_immediately() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends one request
        remote_send_global_request(&mut remote_writer, "test", true, "data").await;

        // Accept, decode, but drop without responding → auto-failure at ticket 0
        {
            let req = match conv.accept().await.unwrap() {
                IncomingGlobal::Request(r) => r,
                _ => panic!("expected Request"),
            };
            let (_payload, _decoded): (SshString, _) = req.decode_payload().await.unwrap();
            // Drop DecodedGlobalRequest here: writer ticket 0 → auto-failure
        }

        // The auto-failure (ticket 0) IS the current serving ticket.
        // Sending a notify should drain it before sending the notify.
        let notice = TestNotice {
            payload: TestPayload(SshString::from_static("after-auto")),
        };
        conv.notify::<TestNotice, _>(&notice).await.unwrap();

        // Remote should see: failure response, then the notify
        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, SSH_MSG_REQUEST_FAILURE);

        let (rt, wr) = remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(rt.as_ref() as &[u8], b"test-notice");
        assert!(!wr);
    }

    // -- Mixed auto-failures and real responses ----------------------------

    #[tokio::test]
    async fn auto_failures_interleaved_with_real_responses() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends 4 requests: A, B, C, D (all want_reply)
        for label in ["A", "B", "C", "D"] {
            remote_send_global_request(&mut remote_writer, label, true, label).await;
        }

        // Accept all 4
        let mut decoded_reqs: Vec<DecodedGlobalRequest<TestManageStream>> = Vec::new();
        for _ in 0..4 {
            match conv.accept().await.unwrap() {
                IncomingGlobal::Request(r) => {
                    let (_payload, decoded): (SshString, _) =
                        r.decode_payload().await.unwrap();
                    decoded_reqs.push(decoded);
                }
                _ => panic!("expected Request"),
            }
        }

        // Respond to A (ticket 0) with success
        let a = decoded_reqs.remove(0);
        a.respond_success(VarInt::from_u32(1)).await.unwrap();

        // Drop B (ticket 1) → auto-failure
        let _b = decoded_reqs.remove(0);
        drop(_b);

        // Respond to C (ticket 2) with failure
        let c = decoded_reqs.remove(0);
        c.respond_failure().await.unwrap();

        // Drop D (ticket 3) → auto-failure
        let _d = decoded_reqs.remove(0);
        drop(_d);

        // Now send a notify to drain remaining auto-failures
        let notice = TestNotice {
            payload: TestPayload(SshString::from_static("end")),
        };
        conv.notify::<TestNotice, _>(&notice).await.unwrap();

        // Remote expects: success(1), failure(B-auto), failure(C), failure(D-auto), notify
        let msg_a: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_a, SSH_MSG_REQUEST_SUCCESS);
        let val_a: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(val_a, VarInt::from_u32(1));

        let msg_b: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_b, SSH_MSG_REQUEST_FAILURE); // B auto-failure

        let msg_c: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_c, SSH_MSG_REQUEST_FAILURE); // C explicit failure

        let msg_d: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_d, SSH_MSG_REQUEST_FAILURE); // D auto-failure

        // Notify
        let (rt, wr) = remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(rt.as_ref() as &[u8], b"test-notice");
        assert!(!wr);
    }

    // -- Type-system guarantees (compile-time) --------------------------------
    // The following invariants are now enforced at compile time:
    // - Cannot decode twice: decode_payload consumes self
    // - Cannot respond before decode: respond methods are on DecodedGlobalRequest
    // - Cannot respond twice: respond methods consume self
    // No runtime tests needed for these cases.

    // -- OrderedAccess unit-level tests ------------------------------------

    #[tokio::test]
    async fn ordered_access_sequential_tickets() {
        let access = OrderedAccess::new(42u32);
        let poisoned = AtomicBool::new(false);

        let t0 = access.take_ticket();
        let t1 = access.take_ticket();
        let t2 = access.take_ticket();

        assert_eq!(t0, 0);
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);

        // Ticket 0 can acquire immediately
        {
            let guard = access.acquire(t0, &poisoned).await.unwrap();
            assert_eq!(*guard, 42);
            // drop → advances current_serving to 1
        }

        // Now ticket 1 can acquire
        {
            let mut guard = access.acquire(t1, &poisoned).await.unwrap();
            *guard = 99;
            // drop → advances current_serving to 2
        }

        // Now ticket 2 can acquire
        {
            let guard = access.acquire(t2, &poisoned).await.unwrap();
            assert_eq!(*guard, 99); // modified by ticket 1
        }
    }

    #[tokio::test]
    async fn ordered_access_concurrent_tickets() {
        let access = Arc::new(OrderedAccess::new(Vec::<u32>::new()));
        let poisoned = Arc::new(AtomicBool::new(false));

        let t0 = access.take_ticket();
        let t1 = access.take_ticket();
        let t2 = access.take_ticket();

        let mut handles = Vec::new();

        // Launch tickets in REVERSE order — they should still execute in order.
        for (ticket, value) in [(t2, 3u32), (t1, 2), (t0, 1)] {
            let access_clone = Arc::clone(&access);
            let poisoned_clone = Arc::clone(&poisoned);
            handles.push(tokio::spawn(async move {
                let mut guard = access_clone.acquire(ticket, &poisoned_clone).await.unwrap();
                guard.push(value);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Verify order: t0 ran first (pushed 1), then t1 (2), then t2 (3)
        let guard = {
            let t = access.take_ticket();
            access.acquire(t, &poisoned).await.unwrap()
        };
        assert_eq!(&*guard, &[1, 2, 3]);
    }

    #[tokio::test]
    async fn ordered_access_poison_wakes_waiters() {
        let access = Arc::new(OrderedAccess::new(()));
        let poisoned = Arc::new(AtomicBool::new(false));

        // Take ticket 0 but don't release — ticket 1 will wait forever.
        let t0 = access.take_ticket();
        let t1 = access.take_ticket();

        let _guard0 = access.acquire(t0, &poisoned).await.unwrap();

        let access_clone = Arc::clone(&access);
        let poisoned_clone = Arc::clone(&poisoned);
        let handle = tokio::spawn(async move {
            access_clone.acquire(t1, &poisoned_clone).await
        });

        // Give the spawned task time to start waiting
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Poison — should wake the waiter
        poisoned.store(true, Ordering::SeqCst);
        access.notify_waiters();

        let result = handle.await.unwrap();
        assert!(result.is_err());
    }

    // -- Request with notification mixed on reader -------------------------

    #[tokio::test]
    async fn accept_alternating_requests_and_notices() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Remote sends: request, notice, request, notice
        remote_send_global_request(&mut remote_writer, "req-1", true, "r1").await;
        remote_send_global_request(&mut remote_writer, "ntf-1", false, "n1").await;
        remote_send_global_request(&mut remote_writer, "req-2", true, "r2").await;
        remote_send_global_request(&mut remote_writer, "ntf-2", false, "n2").await;

        // Accept #1: request
        {
            let req = match conv.accept().await.unwrap() {
                IncomingGlobal::Request(r) => r,
                _ => panic!("expected Request"),
            };
            assert_eq!(req.request_type().as_ref() as &[u8], b"req-1");
            let (_, decoded): (SshString, _) = req.decode_payload().await.unwrap();
            decoded.respond_success(VarInt::from_u32(10)).await.unwrap();
        }

        // Accept #2: notice
        {
            let ntf = match conv.accept().await.unwrap() {
                IncomingGlobal::Notify(n) => n,
                _ => panic!("expected Notify"),
            };
            assert_eq!(ntf.request_type().as_ref() as &[u8], b"ntf-1");
            let _: SshString = ntf.decode_payload().await.unwrap();
        }

        // Accept #3: request
        {
            let req = match conv.accept().await.unwrap() {
                IncomingGlobal::Request(r) => r,
                _ => panic!("expected Request"),
            };
            assert_eq!(req.request_type().as_ref() as &[u8], b"req-2");
            let (_, decoded): (SshString, _) = req.decode_payload().await.unwrap();
            decoded.respond_failure().await.unwrap();
        }

        // Accept #4: notice
        {
            let ntf = match conv.accept().await.unwrap() {
                IncomingGlobal::Notify(n) => n,
                _ => panic!("expected Notify"),
            };
            assert_eq!(ntf.request_type().as_ref() as &[u8], b"ntf-2");
            let _: SshString = ntf.decode_payload().await.unwrap();
        }

        // Remote should see: success(10), then failure
        let msg_1: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_1, SSH_MSG_REQUEST_SUCCESS);
        let val_1: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(val_1, VarInt::from_u32(10));

        let msg_2: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_2, SSH_MSG_REQUEST_FAILURE);
    }

    // -- decode_payload success releases reader for next accept ---------------

    #[tokio::test]
    async fn decode_payload_success_releases_reader() {
        let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

        // Send two requests
        remote_send_global_request(&mut remote_writer, "first", true, "x").await;
        remote_send_global_request(&mut remote_writer, "second", false, "y").await;

        // Accept and decode first request
        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };
        let (payload, _decoded): (SshString, _) = req.decode_payload().await.unwrap();
        assert_eq!(payload.as_ref() as &[u8], b"x");

        // After decode_payload succeeds, the reader is released and we can
        // accept the next message without blocking.
        let ntf = match conv.accept().await.unwrap() {
            IncomingGlobal::Notify(n) => n,
            _ => panic!("expected Notify"),
        };
        let payload: SshString = ntf.decode_payload().await.unwrap();
        assert_eq!(payload.as_ref() as &[u8], b"y");
    }

    // -- Empty request (no payload beyond header) --------------------------

    /// A request type whose payload is empty (zero bytes).
    #[derive(Clone)]
    struct EmptyPayload;

    impl<S: AsyncWrite + Send> EncodeInto<S> for EmptyPayload {
        type Output = ();
        type Error = std::io::Error;

        async fn encode_into(self, _stream: S) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct EmptyRequest;

    impl WantReplyGlobalRequest for EmptyRequest {
        type Success = EmptyPayload;
        type Payload = EmptyPayload;

        fn request_type(&self) -> SshString {
            SshString::from_static("empty")
        }

        fn payload(&self) -> &Self::Payload {
            &EmptyPayload
        }
    }

    impl<S: AsyncRead + Send> DecodeFrom<S> for EmptyPayload {
        type Error = std::io::Error;

        async fn decode_from(_stream: S) -> Result<Self, Self::Error> {
            Ok(EmptyPayload)
        }
    }

    #[tokio::test]
    async fn request_with_empty_payload() {
        let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

        // Pre-send empty success response
        remote_writer
            .encode_one(VarInt::from_u32(81)) // SUCCESS
            .await
            .unwrap();
        // No success body — EmptyPayload reads nothing
        AsyncWriteExt::flush(&mut remote_writer).await.unwrap();

        let result = conv
            .request::<EmptyRequest, _, _>(&EmptyRequest)
            .await;
        assert!(result.is_ok());

        // Remote reads the request header and (empty) payload
        let (rt, wr) = remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(rt.as_ref() as &[u8], b"empty");
        assert!(wr);
        // No payload bytes to read
    }
}
