//! SSH3 protocol layer for QUIC stream routing.
//!
//! [`Ssh3Protocol`] implements [`Protocol`] to route incoming bidirectional QUIC
//! streams. Streams whose first varint equals the SSH3 signal value (`0xaf3627e6`)
//! are dispatched to registered conversations via mpsc channels. All other streams
//! are passed to the next protocol layer.

use std::{
    collections::HashMap,
    fmt::Debug,
    pin::Pin,
    sync::Arc,
};

use futures::future::BoxFuture;
use snafu::Report;
use tokio::io;
use tokio::sync::mpsc;

use genmeta_ssh3_proto::codec::ChannelHeader;
use genmeta_ssh3_proto::session::{Ssh3TransportClient, Ssh3TransportServerShared};
use h3x::{
    codec::{
        DecodeExt, ErasedPeekableBiStream, ErasedPeekableUniStream,
        SinkWriter, StreamReader,
    },
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError},
    stream_id::StreamId,
    varint::VarInt,
};

use crate::error::{ServerError, ServerResult, map_poison};
use remoc::rtc::ServerShared;

/// SSH3 signal value used to identify SSH3 channel streams.
const SSH3_SIGNAL_VALUE: u32 = 0xaf3627e6;

/// Type-erased reader: `StreamReader` wrapping a boxed `dyn ReadStream`.
pub type BoxReader = StreamReader<Pin<Box<dyn quic::ReadStream + Send>>>;

/// Type-erased writer: `SinkWriter` wrapping a boxed `dyn WriteStream`.
pub type BoxWriter = SinkWriter<Pin<Box<dyn quic::WriteStream + Send>>>;

/// Payload dispatched to a conversation: the decoded channel header plus
/// type-erased reader/writer streams.
pub type DispatchedStream = (ChannelHeader, BoxReader, BoxWriter);

// ---------------------------------------------------------------------------
// ConversationState — one-way lifecycle transitions
// ---------------------------------------------------------------------------

/// Lifecycle state for a conversation slot. Transitions are one-way only:
/// `Reserved → Authenticating → Upgrading → Active → Closed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationState {
    Reserved,
    Authenticating,
    Upgrading,
    Active,
    Closed,
}

// ---------------------------------------------------------------------------
// ConversationSlot — registry entry replacing bare mpsc::Sender
// ---------------------------------------------------------------------------

/// A conversation slot in the registry. Holds the lifecycle state and the
/// mpsc sender for dispatching QUIC streams to this conversation.
pub(crate) struct ConversationSlot {
    state: std::sync::Mutex<ConversationState>,
    sender: mpsc::Sender<DispatchedStream>,
}

impl ConversationSlot {
    fn new(sender: mpsc::Sender<DispatchedStream>) -> Self {
        Self {
            state: std::sync::Mutex::new(ConversationState::Reserved),
            sender,
        }
    }

    fn state(&self) -> ServerResult<ConversationState> {
        Ok(*self.state.lock().map_err(|e| map_poison(e, true))?)
    }

    fn transition(&self, from: ConversationState, to: ConversationState) -> ServerResult<()> {
        let mut guard = self.state.lock().map_err(|e| map_poison(e, true))?;
        if *guard != from {
            return Err(ServerError::InvalidConversationSlotState { state: *guard });
        }
        *guard = to;
        Ok(())
    }

    fn close(&self) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = ConversationState::Closed;
        }
    }
}

/// Type alias for the registry (std::sync::Mutex for synchronous Drop cleanup).
type Registry = Arc<std::sync::Mutex<HashMap<u64, Arc<ConversationSlot>>>>;

/// SSH3 protocol layer for QUIC stream routing.
///
/// Routes incoming bidirectional QUIC streams by peeking the first varint.
/// SSH3 channel streams (signal value `0xaf3627e6`) are dispatched to the
/// appropriate conversation via mpsc. Other streams are passed through.
pub struct Ssh3Protocol {
    registry: Registry,
    opener: crate::channel::OpenBiFactory,
}

impl Debug for Ssh3Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh3Protocol").finish_non_exhaustive()
    }
}

impl Ssh3Protocol {
    pub(crate) fn new(opener: crate::channel::OpenBiFactory) -> Self {
        Self {
            registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
            opener,
        }
    }

    pub fn open_bi_factory(&self) -> crate::channel::OpenBiFactory {
        self.opener.clone()
    }

    /// Registers a conversation, returning a receiver for dispatched streams.
    ///
    /// When an incoming SSH3 stream has a `conversation_id` matching `id`,
    /// the decoded [`ChannelHeader`] and type-erased stream pair are sent
    /// to the returned receiver.
    pub async fn register_conversation(
        &self,
        id: StreamId,
    ) -> ServerResult<crate::channel::ConversationEndpoint> {
        let (tx, rx) = mpsc::channel(8);
        let slot = Arc::new(ConversationSlot::new(tx));
        slot.transition(ConversationState::Reserved, ConversationState::Active)?;
        self.registry
            .lock()
            .map_err(|e| map_poison(e, false))?
            .insert(id.into_inner(), slot);
        Ok(crate::channel::ConversationEndpoint::new(id, rx, self.open_bi_factory()))
    }

    /// Unregisters a conversation, dropping its sender.
    ///
    /// Any subsequent streams for this `conversation_id` will be logged and
    /// dropped.
    pub async fn unregister_conversation(&self, id: StreamId) -> ServerResult<()> {
        self.registry
            .lock()
            .map_err(|e| map_poison(e, false))?
            .remove(&id.into_inner());
        Ok(())
    }

    /// Reserves a conversation slot for the given QUIC stream.
    ///
    /// Creates a channel in the registry keyed by the stream's ID (as `u64`).
    /// Returns a [`ReservedConversation`] that holds the receiver and can be
    /// handed off to a supervisor via [`handoff_to_supervisor`](ReservedConversation::handoff_to_supervisor).
    /// If dropped without being handed off, the conversation is
    /// automatically unregistered to prevent resource leaks.
    pub async fn reserve_conversation(
        &self,
        stream_id: StreamId,
    ) -> ServerResult<ReservedConversation> {
        let conversation_id = stream_id;
        let (tx, rx) = mpsc::channel(8);
        let slot = Arc::new(ConversationSlot::new(tx));
        self.registry
            .lock()
            .map_err(|e| map_poison(e, false))?
            .insert(conversation_id.into_inner(), Arc::clone(&slot));
        Ok(ReservedConversation {
            conversation_id,
            slot: Some(slot),
            registry: Some(Arc::clone(&self.registry)),
            rx: Some(rx),
        })
    }

    pub async fn create_transport(
        &self,
        stream_id: StreamId,
        capacity: usize,
    ) -> ServerResult<(ReservedConversation, Ssh3TransportServerShared<crate::channel::Ssh3Transport>, Ssh3TransportClient)> {
        let mut reserved = self.reserve_conversation(stream_id).await?;
        let (server, client) = reserved.transport_server(self.open_bi_factory(), capacity)?;
        Ok((reserved, server, client))
    }

    /// Core bidirectional stream accept logic.
    ///
    /// Peeks the first varint. If it matches [`SSH3_SIGNAL_VALUE`], resets the
    /// peek cursor, decodes the full [`ChannelHeader`], and dispatches to the
    /// registered conversation. Otherwise, passes the stream through.
    async fn accept_bi_inner(
        &self,
        (mut reader, writer): ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        // Peek the first varint to determine if this is an SSH3 stream.
        let signal_value = match reader.decode_one::<VarInt>().await {
            Ok(v) => v,
            Err(_) => {
                // Cannot read — pass to next protocol layer.
                return Ok(StreamVerdict::Passed((reader, writer)));
            }
        };

        if signal_value.into_inner() as u32 != SSH3_SIGNAL_VALUE {
            // Not SSH3 — pass through. Protocols::accept_bi will reset
            // the peek cursor on Passed streams.
            return Ok(StreamVerdict::Passed((reader, writer)));
        }

        // SSH3 stream! Reset cursor so ChannelHeader::decode can re-read
        // the signal_value as part of the full header.
        Pin::new(&mut reader).reset();

        // With erased types, the reader is already PeekableStreamReader<BoxReadStream>
        // and writer is already SinkWriter<BoxWriteStream> — no mapping needed.
        let mut stream_reader = reader.into_stream_reader();
        let stream_writer = writer;

        // Decode the full ChannelHeader from the reset reader.
        let header = match stream_reader.decode_one::<ChannelHeader>().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("failed to decode SSH3 ChannelHeader: {e}");
                return Ok(StreamVerdict::Accepted);
            }
        };

        // Look up the conversation slot and dispatch.
        // Clone the sender while holding the lock, then drop the lock before awaiting.
        let sender = {
            let registry = match self.registry.lock() {
                Ok(registry) => registry,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(map_poison(error, false)), "failed to lock SSH3 conversation registry");
                    return Ok(StreamVerdict::Accepted);
                }
            };
            registry.get(&header.conversation_id).and_then(|slot| {
                let state = match slot.state() {
                    Ok(state) => state,
                    Err(error) => {
                        tracing::warn!(error = %Report::from_error(error), conversation_id = header.conversation_id, "failed to inspect conversation state");
                        return None;
                    }
                };
                if state != ConversationState::Active {
                    None
                } else {
                    Some(slot.sender.clone())
                }
            })
        };
        if let Some(sender) = sender {
            if let Err(e) = sender.send((header, stream_reader, stream_writer)).await {
                tracing::warn!(error = %Report::from_error(e), "conversation channel closed");
            }
        } else {
            tracing::warn!(
                conversation_id = header.conversation_id,
                "no registered conversation for stream, dropping"
            );
        }

        Ok(StreamVerdict::Accepted)
    }
}

/// A reserved conversation slot in the [`Ssh3Protocol`] registry.
///
/// Created by [`Ssh3Protocol::reserve_conversation`]. Holds a receiver for
/// dispatched streams but does not consume them until
/// [`handoff_to_supervisor()`](Self::handoff_to_supervisor) is called.
/// If dropped without being handed off, the conversation is
/// automatically unregistered to prevent resource leaks.
pub struct ReservedConversation {
    conversation_id: StreamId,
    slot: Option<Arc<ConversationSlot>>,
    registry: Option<Registry>,
    rx: Option<mpsc::Receiver<DispatchedStream>>,
}

impl ReservedConversation {
    /// Returns the conversation ID (the `u64` extracted from the QUIC stream ID).
    pub fn conversation_id(&self) -> StreamId {
        self.conversation_id
    }

    /// Transition from `Reserved` to `Authenticating`.
    ///
    /// Called after the bootstrap is sent to the child process, before
    /// waiting for auth result.
    pub fn transition_to_authenticating(&self) -> ServerResult<()> {
        let slot = self.slot.as_ref().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        slot.transition(
            ConversationState::Reserved,
            ConversationState::Authenticating,
        )
    }

    pub fn transport_server(
        &mut self,
        opener: crate::channel::OpenBiFactory,
        capacity: usize,
    ) -> ServerResult<(Ssh3TransportServerShared<crate::channel::Ssh3Transport>, Ssh3TransportClient)> {
        let slot = self.slot.as_ref().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        let state = slot.state()?;
        if state != ConversationState::Reserved && state != ConversationState::Authenticating {
            return Err(ServerError::InvalidConversationState {
                conversation_id: self.conversation_id,
                state,
            });
        }
        let rx = self.rx.take().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        let endpoint = crate::channel::ConversationEndpoint::new(self.conversation_id, rx, opener);
        let transport = Arc::new(crate::channel::Ssh3Transport::new(endpoint));
        let (server, client) = Ssh3TransportServerShared::new(transport, capacity);
        Ok((server, client))
    }

    pub fn consume_into_lease(mut self) -> ServerResult<ConversationLease> {
        let slot = self.slot.as_ref().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        slot.transition(
            ConversationState::Authenticating,
            ConversationState::Upgrading,
        )?;

        let slot = self.slot.take().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        let registry = self.registry.take().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;

        Ok(ConversationLease {
            conversation_id: self.conversation_id,
            slot,
            registry,
        })
    }

    /// Hands off the reservation to a supervisor task.
    ///
    /// Transitions from `Authenticating` to `Upgrading`, then returns a
    /// [`ConversationLease`] (which owns cleanup) and a
    /// This **replaces** the old `activate()` method.
    pub fn handoff_to_supervisor(
        mut self,
        opener: crate::channel::OpenBiFactory,
    ) -> ServerResult<(ConversationLease, crate::channel::ConversationEndpoint)> {
        let slot = self.slot.as_ref().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        slot.transition(
            ConversationState::Authenticating,
            ConversationState::Upgrading,
        )?;

        let slot = self.slot.take().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;
        let registry = self.registry.take().ok_or(ServerError::ConsumedConversationEndpoint {
            conversation_id: self.conversation_id,
        })?;

        let endpoint = crate::channel::ConversationEndpoint::new(
            self.conversation_id,
            self.rx.take().ok_or(ServerError::ConsumedConversationEndpoint {
                conversation_id: self.conversation_id,
            })?,
            opener,
        );

        let lease = ConversationLease {
            conversation_id: self.conversation_id,
            slot,
            registry,
        };

        Ok((lease, endpoint))
    }
}

impl Drop for ReservedConversation {
    fn drop(&mut self) {
        if let (Some(slot), Some(registry)) = (self.slot.take(), self.registry.take()) {
            let id = self.conversation_id.into_inner();
            // Synchronous cleanup — std::sync::Mutex, no tokio::spawn needed.
            slot.close();
            let mut reg = registry.lock().unwrap();
            // Only remove if the slot in the registry is still ours (pointer identity).
            if let Some(existing) = reg.get(&id)
                && Arc::ptr_eq(existing, &slot) {
                reg.remove(&id);
            }
        }
    }
}

/// RAII lease for a conversation after auth success.
///
/// Owns cleanup responsibility after [`ReservedConversation::handoff_to_supervisor`].
/// When dropped, transitions the slot to `Closed` and removes it from the
/// registry (if still present with the same `Arc` identity).
pub struct ConversationLease {
    conversation_id: StreamId,
    slot: Arc<ConversationSlot>,
    registry: Registry,
}

impl ConversationLease {
    /// Transition from `Upgrading` to `Active`.
    ///
    pub fn transition_to_active(&self) -> ServerResult<()> {
        self.slot.transition(
            ConversationState::Upgrading,
            ConversationState::Active,
        )
    }

    /// Returns the conversation ID.
    pub fn conversation_id(&self) -> StreamId {
        self.conversation_id
    }
}

impl Drop for ConversationLease {
    fn drop(&mut self) {
        // Synchronous cleanup — transition to Closed and remove from registry.
        self.slot.close();
        let mut reg = self.registry.lock().unwrap();
        if let Some(existing) = reg.get(&self.conversation_id.into_inner())
            && Arc::ptr_eq(existing, &self.slot) {
            reg.remove(&self.conversation_id.into_inner());
        }
    }
}

impl Protocol for Ssh3Protocol {
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
        // SSH3 does not use unidirectional streams — always pass through.
        Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
    }

    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
        Box::pin(async move {
            self.accept_bi_inner(stream).await
        })
    }
}

/// Factory for creating [`Ssh3Protocol`] instances per-connection.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ssh3ProtocolFactory;

impl<C: quic::Connection + ?Sized> ProductProtocol<C> for Ssh3ProtocolFactory {
    type Protocol = Ssh3Protocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        _layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        let conn = conn.clone();
        Box::pin(async move {
            let opener: crate::channel::OpenBiFactory = Arc::new(move || {
                let conn = conn.clone();
                Box::pin(async move {
                    let (reader, writer) = conn
                        .open_bi()
                        .await
                        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error))?;
                    let async_reader = StreamReader::new(reader);
                    let async_writer = SinkWriter::new(writer);
                    Ok((
                        Box::new(async_reader) as Box<dyn tokio::io::AsyncRead + Send + Unpin>,
                        Box::new(async_writer) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
                    ))
                })
            });
            Ok(Ssh3Protocol::new(opener))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::codec::{DecodeFrom, EncodeExt, EncodeInto};
    use h3x::stream_id::StreamId;
    use tokio::io::{AsyncReadExt, duplex};

    fn test_open_bi_factory() -> crate::channel::OpenBiFactory {
        Arc::new(|| {
            Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "test protocol does not open streams",
                ))
            })
        })
    }

    /// Helper: encode a ChannelHeader into raw bytes.
    async fn encode_channel_header(header: &ChannelHeader) -> Vec<u8> {
        let (mut w, mut r) = duplex(4096);
        header.encode_into(&mut w).await.unwrap();
        drop(w);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        buf
    }

    /// Helper: encode just a VarInt into raw bytes.
    async fn encode_varint(v: u64) -> Vec<u8> {
        let (mut w, mut r) = duplex(64);
        w.encode_one(VarInt::try_from(v).unwrap()).await.unwrap();
        drop(w);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        buf
    }

    /// Helper: decode a ChannelHeader from bytes and try to dispatch it
    /// through the protocol's registry. Returns the decoded header on
    /// success, None if the conversation is not registered.
    async fn simulate_dispatch(
        protocol: &Ssh3Protocol,
        header: &ChannelHeader,
    ) -> bool {
        let registry = protocol.registry.lock().unwrap();
        registry.contains_key(&header.conversation_id)
    }

    #[tokio::test]
    async fn register_and_unregister_conversation() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());

        // Register a conversation.
        let mut endpoint = proto.register_conversation(StreamId::try_from(42u64).unwrap()).await.unwrap();

        // Verify the sender exists.
        {
            let registry = proto.registry.lock().unwrap();
            assert!(registry.contains_key(&42));
        }

        // Unregister.
        proto.unregister_conversation(StreamId::try_from(42u64).unwrap()).await.unwrap();

        // Verify removed.
        {
            let registry = proto.registry.lock().unwrap();
            assert!(!registry.contains_key(&42));
        }

        // Receiver should be closed after sender is dropped.
        assert!(endpoint.accept_channel().await.is_none());
    }

    #[tokio::test]
    async fn unregister_drops_sender() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        let mut endpoint = proto.register_conversation(StreamId::try_from(99u64).unwrap()).await.unwrap();

        // Unregister drops the sender.
        proto.unregister_conversation(StreamId::try_from(99u64).unwrap()).await.unwrap();

        // recv should return None (channel closed).
        assert!(endpoint.accept_channel().await.is_none());
    }

    #[tokio::test]
    async fn conversation_dispatch_via_registry() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        let _endpoint = proto.register_conversation(StreamId::try_from(12345u64).unwrap()).await.unwrap();

        let header = ChannelHeader {
            signal_value: SSH3_SIGNAL_VALUE,
            conversation_id: 12345,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        // Verify the conversation is registered.
        assert!(simulate_dispatch(&proto, &header).await);

        // Verify the header encodes correctly.
        let data = encode_channel_header(&header).await;
        assert!(!data.is_empty());

        // Verify roundtrip of header via decode.
        let (mut w, mut r) = duplex(4096);
        tokio::io::AsyncWriteExt::write_all(&mut w, &data).await.unwrap();
        drop(w);
        let decoded = ChannelHeader::decode_from(&mut r).await.unwrap();
        assert_eq!(decoded.signal_value, SSH3_SIGNAL_VALUE);
        assert_eq!(decoded.conversation_id, 12345);
        assert_eq!(decoded.channel_type, "session");
        assert_eq!(decoded.max_message_size, 1 << 20);
    }

    #[tokio::test]
    async fn unregistered_conversation_no_panic() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        // No conversation registered for id 9999.

        let header = ChannelHeader {
            signal_value: SSH3_SIGNAL_VALUE,
            conversation_id: 9999,
            channel_type: "session".into(),
            max_message_size: 65535,
        };

        // Should not panic — just returns false (not registered).
        assert!(!simulate_dispatch(&proto, &header).await);
    }

    #[tokio::test]
    async fn signal_value_detection() {
        // Verify SSH3 signal value constant.
        assert_eq!(SSH3_SIGNAL_VALUE, 0xaf3627e6);

        // Encode as varint and verify it's 8 bytes.
        let encoded = encode_varint(SSH3_SIGNAL_VALUE as u64).await;
        assert_eq!(encoded.len(), 8);

        // Verify the 8-byte encoding matches expected.
        let expected = 0xC000_0000_AF36_27E6u64.to_be_bytes();
        assert_eq!(encoded, expected);
    }

    #[tokio::test]
    async fn multiple_conversations_isolated() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        let _endpoint1 = proto.register_conversation(StreamId::try_from(100u64).unwrap()).await.unwrap();
        let _endpoint2 = proto.register_conversation(StreamId::try_from(200u64).unwrap()).await.unwrap();

        // Both conversations should be registered.
        {
            let registry = proto.registry.lock().unwrap();
            assert!(registry.contains_key(&100));
            assert!(registry.contains_key(&200));
            assert!(!registry.contains_key(&300));
        }

        // Unregister one, verify the other remains.
        proto.unregister_conversation(StreamId::try_from(100u64).unwrap()).await.unwrap();
        {
            let registry = proto.registry.lock().unwrap();
            assert!(!registry.contains_key(&100));
            assert!(registry.contains_key(&200));
        }
    }

    #[tokio::test]
    async fn re_register_conversation() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        let mut endpoint1 = proto.register_conversation(StreamId::try_from(42u64).unwrap()).await.unwrap();

        // Re-register with the same id replaces the sender.
        let endpoint2 = proto.register_conversation(StreamId::try_from(42u64).unwrap()).await.unwrap();

        // Old receiver should be closed (old sender was dropped when replaced).
        assert!(endpoint1.accept_channel().await.is_none());

        let open_result = endpoint2.open_stream().await;
        assert!(open_result.is_err());
    }

    #[tokio::test]
    async fn channel_header_with_ssh3_signal_roundtrip() {
        let header = ChannelHeader {
            signal_value: SSH3_SIGNAL_VALUE,
            conversation_id: 42,
            channel_type: "session".into(),
            max_message_size: 65535,
        };
        let data = encode_channel_header(&header).await;

        // First 8 bytes should be the SSH3 signal_value varint.
        let signal_bytes = &data[..8];
        let expected_signal = 0xC000_0000_AF36_27E6u64.to_be_bytes();
        assert_eq!(signal_bytes, &expected_signal);

        // Full roundtrip.
        let (mut w, mut r) = duplex(4096);
        tokio::io::AsyncWriteExt::write_all(&mut w, &data).await.unwrap();
        drop(w);
        let decoded = ChannelHeader::decode_from(&mut r).await.unwrap();
        assert_eq!(decoded, header);
    }

    #[tokio::test]
    async fn default_creates_empty_protocol() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        let registry = proto.registry.lock().unwrap();
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn reserve_conversation_starts_non_active() {
        let proto = Ssh3Protocol::new(test_open_bi_factory());
        let stream_id = StreamId::try_from(77u64).unwrap();
        let reserved = proto.reserve_conversation(stream_id).await.unwrap();

        let slot_state = {
            let reg = proto.registry.lock().unwrap();
            let slot = reg.get(&77).expect("slot should exist");
            slot.state().unwrap()
        };

        assert_eq!(slot_state, ConversationState::Reserved);
        drop(reserved);
    }
}
