//! SSH3 protocol layer — identifies and dispatches SSH3 channel streams.
//!
//! [`Ssh3Protocol`] implements [`h3x::protocol::Protocol`] and participates in the
//! h3x layered stream-routing architecture. It:
//!
//! 1. Peeks the first VarInt of each inbound bidi stream.
//! 2. If the value equals [`SIGNAL_VALUE`], reads the full [`ChannelStreamHeader`]
//!    and routes the stream to the registered [`LocalConversation`].
//! 3. Otherwise resets the peek cursor and returns `StreamVerdict::Passed` so the
//!    next layer (DHttpProtocol / WebTransport / …) can handle it.
//!
//! Uni-directional streams are not used by SSH3; they are always passed through.

use std::{
    collections::HashMap,
    fmt,
    pin::Pin,
    sync::Arc,
};

use futures::future::BoxFuture;
use h3x::{
    codec::{BoxPeekableBiStream, BoxPeekableUniStream, DecodeExt},
    connection::{QuicConnection, StreamError},
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError},
    varint::VarInt,
};
use proto::{
    codec::{ChannelStreamHeader, ConversationId, SIGNAL_VALUE},
    conversation::{LocalConversation, Ssh3BiStream},
};
use tokio::io::AsyncReadExt;
use tokio::sync::{RwLock, mpsc};
use tracing::Instrument;

// ---------------------------------------------------------------------------
// Ssh3Protocol
// ---------------------------------------------------------------------------

/// SSH3 protocol layer that identifies channel streams and routes them to
/// registered conversations.
pub struct Ssh3Protocol<C: quic::Connection + ?Sized> {
    /// Map from conversation ID to the mpsc sender for inbound channel streams.
    conversations: Arc<RwLock<HashMap<ConversationId, mpsc::Sender<Ssh3BiStream<C>>>>>,
}

impl<C: quic::Connection + ?Sized> fmt::Debug for Ssh3Protocol<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ssh3Protocol").finish_non_exhaustive()
    }
}

impl<C: quic::Connection + ?Sized> Ssh3Protocol<C> {
    /// Create a new `Ssh3Protocol` with an empty conversation map.
    pub fn new() -> Self {
        Self {
            conversations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Deregister a conversation (e.g. on session close).
    pub async fn deregister(&self, conversation_id: ConversationId) {
        self.conversations.write().await.remove(&conversation_id);
        tracing::debug!(conversation_id = %conversation_id, "deregistered conversation");
    }

    /// Core logic for `accept_bi`: peek signal, parse header, dispatch.
    async fn handle_bi<C2: quic::Connection + ?Sized>(
        conversations: Arc<RwLock<HashMap<ConversationId, mpsc::Sender<Ssh3BiStream<C2>>>>>,
        mut stream: BoxPeekableBiStream<C2>,
    ) -> Result<StreamVerdict<BoxPeekableBiStream<C2>>, StreamError>
    where
        <C2 as quic::ManageStream>::StreamReader: Unpin + Send,
    {
        let (ref mut reader, _) = stream;

        // Read the first VarInt — the signal value.
        let signal = match reader.decode_one::<VarInt>().await {
            Ok(v) => v,
            Err(_) => {
                // Stream closed or error before we could read the signal.
                return Ok(StreamVerdict::Passed(stream));
            }
        };

        if signal.into_inner() != SIGNAL_VALUE as u64 {
            // Not our stream — reset the peek cursor and pass to the next layer.
            Pin::new(&mut stream.0).reset();
            return Ok(StreamVerdict::Passed(stream));
        }

        // It is an SSH3 channel stream. Parse the remaining header fields.
        let header = match read_header_fields(reader).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse SSH3 channel stream header");
                return Err(e);
            }
        };

        let conv_id = header.conversation_id;

        // Commit the peeked bytes — the header is consumed.
        Pin::new(&mut stream.0).commit();

        // Route to the registered conversation.
        let guard = conversations.read().await;
        if let Some(sender) = guard.get(&conv_id) {
            if sender.send(stream).await.is_err() {
                tracing::warn!(
                    conversation_id = %conv_id,
                    "inbound channel stream dropped — conversation closed"
                );
            } else {
                tracing::debug!(
                    conversation_id = %conv_id,
                    channel_type = %header.channel_type,
                    "dispatched channel stream"
                );
            }
        } else {
            tracing::warn!(
                conversation_id = %conv_id,
                "received channel stream for unknown conversation"
            );
        }

        Ok(StreamVerdict::Accepted)
    }
}

/// Methods that require `C: Sized` (since `LocalConversation<C>` has a `Sized` bound on `C`).
impl<C: quic::Connection> Ssh3Protocol<C> {
    /// Register a conversation so that inbound channel streams are routed to it.
    ///
    /// The caller should hold the `LocalConversation` and ensure they call
    /// `deregister` before dropping it.
    pub async fn register(&self, conv: &LocalConversation<C>) {
        let id = conv.conversation_id();
        let sender = conv.inbound_sender();
        self.conversations.write().await.insert(id, sender);
        tracing::debug!(conversation_id = %id, "registered conversation");
    }
}

impl<C: quic::Connection + ?Sized> Default for Ssh3Protocol<C> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// h3x Protocol impl
// ---------------------------------------------------------------------------

impl<C> Protocol<C> for Ssh3Protocol<C>
where
    C: quic::Connection + ?Sized,
    <C as quic::ManageStream>::StreamReader: Unpin + Send,
{
    fn accept_uni<'a>(
        &'a self,
        _connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableUniStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>> {
        // SSH3 does not use unidirectional streams — always pass through.
        Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
    }

    fn accept_bi<'a>(
        &'a self,
        _connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableBiStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
        let conversations = self.conversations.clone();
        Box::pin(
            Self::handle_bi::<C>(conversations, stream)
                .in_current_span(),
        )
    }
}

// ---------------------------------------------------------------------------
// Ssh3ProtocolFactory (ProductProtocol)
// ---------------------------------------------------------------------------

/// Factory for [`Ssh3Protocol`] — implements [`ProductProtocol`] so that h3x
/// can initialise the SSH3 layer during connection setup.
#[derive(Debug, Clone, Default)]
pub struct Ssh3ProtocolFactory;

impl<C> ProductProtocol<C> for Ssh3ProtocolFactory
where
    C: quic::Connection + ?Sized,
    <C as quic::ManageStream>::StreamReader: Unpin + Send,
{
    type Protocol = Ssh3Protocol<C>;

    fn init<'a>(
        &'a self,
        _conn: &'a Arc<QuicConnection<C>>,
        _layers: &'a Protocols<C>,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        Box::pin(async move { Ok(Ssh3Protocol::new()) })
    }
}

// ---------------------------------------------------------------------------
// Helper: read the remaining header fields after the signal VarInt
// ---------------------------------------------------------------------------

/// Read conversation_id, channel_type_len, channel_type, max_message_size from
/// the stream, following the signal VarInt already consumed.
async fn read_header_fields<R>(reader: &mut R) -> Result<ChannelStreamHeader, StreamError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    // conversation_id (VarInt)
    let conv_raw = reader
        .decode_one::<VarInt>()
        .await
        .map_err(StreamError::from)?;
    let conversation_id = ConversationId::new(conv_raw.into_inner());

    // channel_type length (VarInt)
    let ct_len = reader
        .decode_one::<VarInt>()
        .await
        .map_err(StreamError::from)?;
    let ct_len = ct_len.into_inner() as usize;

    // channel_type string
    let mut ct_buf = vec![0u8; ct_len];
    reader
        .read_exact(&mut ct_buf)
        .await
        .map_err(StreamError::from)?;
    let channel_type = String::from_utf8(ct_buf).map_err(|_| {
        StreamError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SSH3 channel type is not valid UTF-8",
        ))
    })?;

    // max_message_size (VarInt)
    let max_msg = reader
        .decode_one::<VarInt>()
        .await
        .map_err(StreamError::from)?;

    Ok(ChannelStreamHeader::new(
        conversation_id,
        channel_type,
        max_msg.into_inner(),
    ))
}
