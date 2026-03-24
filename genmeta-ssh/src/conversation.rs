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
    stream_id::StreamId,
    varint::VarInt,
};
use snafu::ResultExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::pin::Pin;
use tokio::sync::Notify;

use crate::channel::ChannelOpenFailure;
use crate::codec::{SshBool, SshString};

use self::global::PoisonOnDrop;

/// Type-erased control stream reader.
type ControlReader = Pin<Box<dyn AsyncRead + Send>>;
/// Type-erased control stream writer.
type ControlWriter = Pin<Box<dyn AsyncWrite + Send>>;

const SSH_MSG_GLOBAL_REQUEST: VarInt = VarInt::from_u32(80);
const SSH_MSG_REQUEST_SUCCESS: VarInt = VarInt::from_u32(81);
const SSH_MSG_REQUEST_FAILURE: VarInt = VarInt::from_u32(82);

const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: VarInt = VarInt::from_u32(91);
const SSH_MSG_CHANNEL_OPEN_FAILURE: VarInt = VarInt::from_u32(92);
const SSH_MSG_CHANNEL_DATA: VarInt = VarInt::from_u32(94);
const SSH_MSG_CHANNEL_EXTENDED_DATA: VarInt = VarInt::from_u32(95);
const SSH_MSG_CHANNEL_EOF: VarInt = VarInt::from_u32(96);
const SSH_MSG_CHANNEL_CLOSE: VarInt = VarInt::from_u32(97);
const SSH_MSG_CHANNEL_REQUEST: VarInt = VarInt::from_u32(98);
const SSH_MSG_CHANNEL_SUCCESS: VarInt = VarInt::from_u32(99);
const SSH_MSG_CHANNEL_FAILURE: VarInt = VarInt::from_u32(100);

/// SSH extended data type for stderr (RFC 4254 Section 5.2).
pub const SSH_EXTENDED_DATA_STDERR: VarInt = VarInt::from_u32(1);

// ===========================================================================
// Channel open response reader (shared helper)
// ===========================================================================

/// Read and validate a channel open response (confirmation or failure).
///
/// This is the initiator-side counterpart of [`PendingChannel::accept`] /
/// [`PendingChannel::reject`]. Used by [`Conversation::open_channel`] and
/// by direct callers that bypass the `Conversation` layer (e.g. the client).
pub async fn read_channel_open_response<R: AsyncRead + Unpin + Send>(
    reader: &mut R,
) -> Result<(), AwaitOpenError> {
    use self::channel::await_open_error::*;

    let msg_type: VarInt = reader.decode_one().await.context(DecodeMessageTypeSnafu)?;
    match msg_type {
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
            let _max_message_size: VarInt = reader
                .decode_one()
                .await
                .context(DecodeMaxMessageSizeSnafu)?;
            Ok(())
        }
        SSH_MSG_CHANNEL_OPEN_FAILURE => {
            let reason_code: VarInt = reader
                .decode_one()
                .await
                .context(DecodeReasonCodeSnafu)?;
            let description: SshString = reader
                .decode_one()
                .await
                .context(DecodeDescriptionSnafu)?;
            Err(AwaitOpenError::Rejected {
                failure: ChannelOpenFailure {
                    reason_code,
                    description,
                },
            })
        }
        other => Err(AwaitOpenError::UnexpectedMessageType {
            message_type: other,
        }),
    }
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
// Channel open trait
// ===========================================================================

/// A channel type that can be opened.
///
/// Implementors define the channel-type-specific payload. The channel type
/// name (e.g. `"session"`, `"direct-tcpip"`) is returned by
/// [`channel_type`](Self::channel_type) and written as an SSH string in the
/// channel header. Encode/decode bounds on `Payload` are checked at the
/// call site against the concrete stream types.
pub trait ChannelOpen {
    /// Channel-type-specific payload (e.g. `DirectTcpipRequest` for
    /// `"direct-tcpip"`). Types without extra payload can use `()`.
    type Payload: Clone;

    /// The SSH channel type name.
    fn channel_type(&self) -> SshString;

    /// Reference to the channel-type-specific payload.
    fn payload(&self) -> &Self::Payload;
}

// ===========================================================================
// Channel request traits
// ===========================================================================

/// A channel request that expects a reply (`want_reply = true`).
///
/// Analogous to [`WantReplyGlobalRequest`] but for per-channel requests.
/// Channel requests are sent on the channel's own QUIC stream, not the
/// conversation control stream.
pub trait WantReplyChannelRequest {
    /// Successful response type, decoded directly from the channel stream.
    type Success;

    /// Payload type, encoded directly onto the channel stream.
    type Payload: Clone;

    /// The SSH request type string (e.g. `"pty-req"`, `"exec"`).
    fn request_type(&self) -> SshString;

    /// Reference to the payload.
    fn payload(&self) -> &Self::Payload;
}

/// A channel request that does not expect a reply (`want_reply = false`).
///
/// Analogous to [`NotifyGlobalRequest`] but for per-channel requests.
pub trait NotifyChannelRequest {
    /// Payload type, encoded directly onto the channel stream.
    type Payload: Clone;

    /// The SSH request type string (e.g. `"window-change"`, `"exit-status"`).
    fn request_type(&self) -> SshString;

    /// Reference to the payload.
    fn payload(&self) -> &Self::Payload;
}

// ===========================================================================
// EmptyPayload — zero-sized type for encoding/decoding nothing
// ===========================================================================

/// A zero-sized payload for channel types or responses that carry no
/// additional data (e.g. `"session"` channel open, channel success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyPayload;

impl<S: AsyncWrite + Send> EncodeInto<S> for EmptyPayload {
    type Output = ();
    type Error = std::convert::Infallible;

    async fn encode_into(self, _stream: S) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for EmptyPayload {
    type Error = std::convert::Infallible;

    async fn decode_from(_stream: S) -> Result<Self, Self::Error> {
        Ok(EmptyPayload)
    }
}

// ===========================================================================
// ManageSessionStream trait
// ===========================================================================

/// Trait for managing QUIC stream creation and acceptance.
///
/// Implementations handle the transport-specific framing (e.g. SSH3 signal
/// value and session ID). The [`Conversation`] receives streams already
/// positioned past transport framing.
pub trait ManageSessionStream: Send + Sync {
    type StreamReader: AsyncRead + Unpin + Send;
    type StreamWriter: AsyncWrite + Unpin + Send;
    type Error: std::error::Error + Send + Sync + 'static;

    fn open_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::Error>> + Send;

    fn accept_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::Error>> + Send;
}

#[allow(dead_code)] // Server-side bridge; used by server binary, not within library.
pub mod remoc;

// ===========================================================================
// Conversation shared state
// ===========================================================================

struct ConversationShared {
    reader: OrderedAccess<Pin<Box<dyn AsyncRead + Send>>>,
    writer: OrderedAccess<Pin<Box<dyn AsyncWrite + Send>>>,
    poisoned: AtomicBool,
    /// Lock to atomically allocate paired (writer, reader) tickets for
    /// outgoing requests, ensuring send order matches receive order.
    ticket_pair_lock: std::sync::Mutex<()>,
    /// Writer tickets that should automatically send a failure response.
    /// Populated when an [`IncomingGlobalRequest`] is dropped after decoding
    /// but before responding.
    auto_failures: std::sync::Mutex<BTreeSet<u64>>,
}

impl ConversationShared {
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
    ) -> Result<OrderedGuard<Pin<Box<dyn AsyncWrite + Send>>>, SessionPoisonedError> {
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
    peer_version: String,
    shared: Arc<ConversationShared>,
    _manage_stream: M,
}

impl<M: ManageSessionStream> Conversation<M> {
    pub fn new(
        id: StreamId,
        peer_version: impl Into<String>,
        control_stream_reader: impl AsyncRead + Unpin + Send + 'static,
        control_stream_writer: impl AsyncWrite + Unpin + Send + 'static,
        manage_stream: M,
    ) -> Self {
        Self {
            id,
            peer_version: peer_version.into(),
            shared: Arc::new(ConversationShared {
                reader: OrderedAccess::new(Box::pin(control_stream_reader)),
                writer: OrderedAccess::new(Box::pin(control_stream_writer)),
                poisoned: AtomicBool::new(false),
                ticket_pair_lock: std::sync::Mutex::new(()),
                auto_failures: std::sync::Mutex::new(BTreeSet::new()),
            }),
            _manage_stream: manage_stream,
        }
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    pub fn peer_version(&self) -> &str {
        &self.peer_version
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
        for<'w> R::Payload: EncodeInto<&'w mut ControlWriter, Output = (), Error = PE>,
        for<'r> R::Success: DecodeFrom<&'r mut ControlReader, Error = SE>,
    {
        use self::global::send_request_error::*;

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
        for<'w> N::Payload: EncodeInto<&'w mut ControlWriter, Output = (), Error = PE>,
    {
        use self::global::send_notify_error::*;

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
    pub async fn accept(&self) -> Result<IncomingGlobal, AcceptError> {
        use self::global::accept_error::*;

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
            Ok(IncomingGlobal::Request(IncomingGlobalRequest::new(
                request_type,
                guard,
                write_ticket,
                Arc::clone(&self.shared),
            )))
        } else {
            Ok(IncomingGlobal::Notify(IncomingGlobalNotice::new(
                request_type,
                guard,
                Arc::clone(&self.shared),
            )))
        }
    }

    // -----------------------------------------------------------------------
    // Channel operations
    // -----------------------------------------------------------------------

    /// Open a new channel.
    ///
    /// The transport framing (signal value and session ID) is written by the
    /// [`ManageSessionStream`] implementation. This method writes the remaining
    /// channel header fields: `max_message_size`, `channel_type`, and the
    /// type-specific payload.
    ///
    /// Returns the (reader, writer) pair for subsequent channel communication.
    pub async fn open_channel<C, PE>(
        &self,
        channel: &C,
        max_message_size: VarInt,
    ) -> Result<(M::StreamReader, M::StreamWriter), OpenChannelError<M::Error, PE>>
    where
        C: ChannelOpen,
        PE: std::error::Error + Send + Sync + 'static,
        for<'w> C::Payload: EncodeInto<&'w mut M::StreamWriter, Output = (), Error = PE>,
    {
        use self::channel::open_channel_error::*;

        let (mut reader, mut writer) = self
            ._manage_stream
            .open_stream()
            .await
            .context(OpenStreamSnafu)?;

        writer
            .encode_one(max_message_size)
            .await
            .context(EncodeMaxMessageSizeSnafu)?;
        writer
            .encode_one(channel.channel_type())
            .await
            .context(EncodeChannelTypeSnafu)?;
        channel
            .payload()
            .clone()
            .encode_into(&mut writer)
            .await
            .context(EncodePayloadSnafu)?;
        AsyncWriteExt::flush(&mut writer)
            .await
            .context(FlushSnafu)?;

        // Read channel open response (confirmation or failure).
        read_channel_open_response(&mut reader)
            .await
            .context(AwaitConfirmationSnafu)?;

        Ok((reader, writer))
    }

    /// Accept an incoming channel.
    ///
    /// The transport framing (signal value and session ID) has already been
    /// consumed by the [`ManageSessionStream`] implementation. This method
    /// reads the remaining channel header fields: `max_message_size` and
    /// `channel_type`.
    ///
    /// Returns an [`IncomingChannel`] holding the channel type string and the
    /// stream pair. The caller inspects the type string and then calls
    /// [`IncomingChannel::decode_payload`] to decode the type-specific payload.
    pub async fn accept_channel(
        &self,
    ) -> Result<IncomingChannel<M>, AcceptChannelError<M::Error>>
    {
        use self::channel::accept_channel_error::*;

        let (mut reader, writer) = self
            ._manage_stream
            .accept_stream()
            .await
            .context(AcceptStreamSnafu)?;

        let max_message_size: VarInt = reader
            .decode_one()
            .await
            .context(DecodeMaxMessageSizeSnafu)?;
        let channel_type: SshString = reader
            .decode_one()
            .await
            .context(DecodeChannelTypeSnafu)?;

        Ok(IncomingChannel::new(
            channel_type,
            max_message_size,
            reader,
            writer,
        ))
    }
}

// ===========================================================================
// Submodules
// ===========================================================================

mod channel;
mod global;

#[cfg(test)]
mod tests;

pub use channel::{
    AcceptChannelError, AwaitOpenError, ChannelDataRead, ChannelEvent, ChannelResponder,
    IncomingChannel, IncomingChannelRequest, OpenChannelError, PendingChannel,
    ReadChannelEventError, RespondChannelFailureError, RespondChannelSuccessError,
    SendChannelNoticeError, SendChannelRequestError, SshChannel, WriteChannelCloseError,
    WriteChannelEofError, WriteChannelOpenConfirmationError, WriteChannelOpenFailureError,
    WriteDataError, WriteExtendedDataError,
};

pub use global::{
    AcceptError, DecodedGlobalRequest, IncomingGlobal, IncomingGlobalNotice,
    IncomingGlobalRequest, RespondFailureError, RespondSuccessError, SendNotifyError,
    SendRequestError, SessionPoisonedError,
};
