//! SSH3 protocol layer for QUIC stream routing.
//!
//! [`Ssh3Protocol`] implements [`Protocol`] to route incoming bidirectional QUIC
//! streams. Streams whose first varint equals the SSH3 signal value (`0xaf3627e6`)
//! are dispatched to registered conversations via mpsc channels. All other streams
//! are passed to the next protocol layer.

use std::{
    collections::HashMap,
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
};

use futures::future::BoxFuture;
use tokio::io;
use tokio::sync::{Mutex, mpsc};

use genmeta_ssh3_proto::codec::ChannelHeader;
use h3x::{
    codec::{
        DecodeExt, DecodeFrom, ErasedPeekableBiStream, ErasedPeekableUniStream,
        SinkWriter, StreamReader,
    },
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError},
    stream_id::StreamId,
    varint::VarInt,
};

/// SSH3 signal value used to identify SSH3 channel streams.
const SSH3_SIGNAL_VALUE: u32 = 0xaf3627e6;

/// Type-erased reader: `StreamReader` wrapping a boxed `dyn ReadStream`.
pub type BoxReader = StreamReader<Pin<Box<dyn quic::ReadStream + Send>>>;

/// Type-erased writer: `SinkWriter` wrapping a boxed `dyn WriteStream`.
pub type BoxWriter = SinkWriter<Pin<Box<dyn quic::WriteStream + Send>>>;

/// Payload dispatched to a conversation: the decoded channel header plus
/// type-erased reader/writer streams.
pub type DispatchedStream = (ChannelHeader, BoxReader, BoxWriter);

/// SSH3 protocol layer for QUIC stream routing.
///
/// Routes incoming bidirectional QUIC streams by peeking the first varint.
/// SSH3 channel streams (signal value `0xaf3627e6`) are dispatched to the
/// appropriate conversation via mpsc. Other streams are passed through.
pub struct Ssh3Protocol {
    registry: Arc<Mutex<HashMap<u64, mpsc::Sender<DispatchedStream>>>>,
    /// Factory for opening server-initiated QUIC bidirectional streams.
    /// Populated from the QUIC connection during `ProductProtocol::init`.
    stream_factory: Mutex<Option<crate::forward::StreamFactory>>,
}

impl Debug for Ssh3Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh3Protocol").finish_non_exhaustive()
    }
}

impl Ssh3Protocol {
    /// Creates a new `Ssh3Protocol` with an empty conversation registry.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            stream_factory: Mutex::new(None),
        }
    }

    /// Creates a new `Ssh3Protocol` with a pre-populated stream factory.
    pub(crate) fn with_stream_factory(stream_factory: crate::forward::StreamFactory) -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            stream_factory: Mutex::new(Some(stream_factory)),
        }
    }

    /// Registers a conversation, returning a receiver for dispatched streams.
    ///
    /// When an incoming SSH3 stream has a `conversation_id` matching `id`,
    /// the decoded [`ChannelHeader`] and type-erased stream pair are sent
    /// to the returned receiver.
    pub async fn register_conversation(
        &self,
        id: u64,
    ) -> mpsc::Receiver<DispatchedStream> {
        let (tx, rx) = mpsc::channel(8);
        self.registry.lock().await.insert(id, tx);
        rx
    }

    /// Unregisters a conversation, dropping its sender.
    ///
    /// Any subsequent streams for this `conversation_id` will be logged and
    /// dropped.
    pub async fn unregister_conversation(&self, id: u64) {
        self.registry.lock().await.remove(&id);
    }

    /// Reserves a conversation slot for the given QUIC stream.
    ///
    /// Creates a channel in the registry keyed by the stream's ID (as `u64`).
    /// Returns a [`ReservedConversation`] that holds the receiver and can be
    /// activated to transition to the active state. If not activated, the
    /// conversation is automatically unregistered on drop.
    pub async fn reserve_conversation(
        &self,
        stream_id: StreamId,
    ) -> io::Result<ReservedConversation> {
        let conversation_id = stream_id.0.into_inner();
        let rx = self.register_conversation(conversation_id).await;
        let stream_factory = self.stream_factory.lock().await.clone();
        Ok(ReservedConversation {
            conversation_id,
            registry: Some(Arc::clone(&self.registry)),
            rx: Some(rx),
            stream_factory,
        })
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
        let header = match ChannelHeader::decode_from(&mut stream_reader).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("failed to decode SSH3 ChannelHeader: {e}");
                return Ok(StreamVerdict::Accepted);
            }
        };

        // Look up the conversation and dispatch.
        let sender = {
            let registry = self.registry.lock().await;
            registry.get(&header.conversation_id).cloned()
        };
        if let Some(sender) = sender {
            if let Err(e) = sender.send((header, stream_reader, stream_writer)).await {
                tracing::warn!("conversation channel closed: {e}");
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
/// dispatched streams but does not consume them until [`activate()`](Self::activate)
/// is called. If dropped without being activated, the conversation is
/// automatically unregistered to prevent resource leaks.
pub struct ReservedConversation {
    conversation_id: u64,
    registry: Option<Arc<Mutex<HashMap<u64, mpsc::Sender<DispatchedStream>>>>>,
    rx: Option<mpsc::Receiver<DispatchedStream>>,
    stream_factory: Option<crate::forward::StreamFactory>,
}

impl ReservedConversation {
    /// Returns the conversation ID (the `u64` extracted from the QUIC stream ID).
    pub fn conversation_id(&self) -> u64 {
        self.conversation_id
    }

    /// Activates the reservation, transitioning to the active state.
    ///
    /// Returns a [`ConversationHandle`](crate::channel::ConversationHandle)
    /// that wraps the channel receiver and embedded stream factory.
    /// After activation, the conversation remains registered and the caller
    /// is responsible for eventually calling
    /// [`Ssh3Protocol::unregister_conversation`].
    pub fn activate(mut self) -> crate::channel::ConversationHandle {
        // Take the registry to prevent Drop from unregistering.
        self.registry.take();
        crate::channel::ConversationHandle::new(
            self.conversation_id,
            self.rx.take().expect("ReservedConversation already consumed"),
            self.stream_factory.take(),
        )
    }
}

impl Drop for ReservedConversation {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.take() {
            let id = self.conversation_id;
            tokio::spawn(async move {
                registry.lock().await.remove(&id);
            });
        }
    }
}

impl Default for Ssh3Protocol {
    fn default() -> Self {
        Self::new()
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
///
/// Implements [`ProductProtocol`] to capture the QUIC connection's `open_bi`
/// capability as an erased [`StreamFactory`](crate::forward::StreamFactory).
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
            // Capture connection's open_bi capability as an erased StreamFactory
            let stream_factory: crate::forward::StreamFactory = Arc::new(move || {
                let conn = conn.clone();
                Box::pin(async move {
                    let (reader, writer) = conn.open_bi().await.map_err(|e| {
                        io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string())
                    })?;
                    let async_reader = StreamReader::new(reader);
                    let async_writer = SinkWriter::new(writer);
                    Ok((
                        Box::new(async_reader) as Box<dyn tokio::io::AsyncRead + Send + Unpin>,
                        Box::new(async_writer) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
                    ))
                }) as Pin<Box<dyn Future<Output = io::Result<(Box<dyn tokio::io::AsyncRead + Send + Unpin>, Box<dyn tokio::io::AsyncWrite + Send + Unpin>)>> + Send>>
            });
            Ok(Ssh3Protocol::with_stream_factory(stream_factory))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::codec::{EncodeExt, EncodeInto};
    use tokio::io::{AsyncReadExt, duplex};

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
        let registry = protocol.registry.lock().await;
        registry.contains_key(&header.conversation_id)
    }

    #[tokio::test]
    async fn register_and_unregister_conversation() {
        let proto = Ssh3Protocol::new();

        // Register a conversation.
        let mut rx = proto.register_conversation(42).await;

        // Verify the sender exists.
        {
            let registry = proto.registry.lock().await;
            assert!(registry.contains_key(&42));
        }

        // Unregister.
        proto.unregister_conversation(42).await;

        // Verify removed.
        {
            let registry = proto.registry.lock().await;
            assert!(!registry.contains_key(&42));
        }

        // Receiver should be closed after sender is dropped.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unregister_drops_sender() {
        let proto = Ssh3Protocol::new();
        let mut rx = proto.register_conversation(99).await;

        // Unregister drops the sender.
        proto.unregister_conversation(99).await;

        // recv should return None (channel closed).
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn conversation_dispatch_via_registry() {
        let proto = Ssh3Protocol::new();
        let _rx = proto.register_conversation(12345).await;

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
        let proto = Ssh3Protocol::new();
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
        let proto = Ssh3Protocol::new();
        let _rx1 = proto.register_conversation(100).await;
        let _rx2 = proto.register_conversation(200).await;

        // Both conversations should be registered.
        {
            let registry = proto.registry.lock().await;
            assert!(registry.contains_key(&100));
            assert!(registry.contains_key(&200));
            assert!(!registry.contains_key(&300));
        }

        // Unregister one, verify the other remains.
        proto.unregister_conversation(100).await;
        {
            let registry = proto.registry.lock().await;
            assert!(!registry.contains_key(&100));
            assert!(registry.contains_key(&200));
        }
    }

    #[tokio::test]
    async fn re_register_conversation() {
        let proto = Ssh3Protocol::new();
        let mut rx1 = proto.register_conversation(42).await;

        // Re-register with the same id replaces the sender.
        let mut rx2 = proto.register_conversation(42).await;

        // Old receiver should be closed (old sender was dropped when replaced).
        assert!(rx1.recv().await.is_none());

        // New receiver should still be open.
        // Verify by checking that try_recv returns Empty (not Disconnected).
        match rx2.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => { /* expected */ }
            _ => panic!("expected Empty from try_recv"),
        }
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
        let proto = Ssh3Protocol::default();
        let registry = proto.registry.lock().await;
        assert!(registry.is_empty());
    }
}
