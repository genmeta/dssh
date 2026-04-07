//! SSH3 protocol layer for h3x stream dispatch.
//!
//! Integrates SSH3 into the h3x layered protocol architecture. The protocol
//! layer identifies incoming SSH3 channel streams by peeking for the channel
//! signal value (`0xaf3627e6`), then routes them to the appropriate
//! conversation based on session ID.
//!
//! # Boundary
//!
//! The protocol layer consumes exactly two fields from each incoming channel
//! stream:
//!
//! 1. The channel signal value ([`VarInt`])
//! 2. The session ID ([`StreamId`])
//!
//! The conversation receives the stream positioned at the `max_message_size`
//! field, which is the start of the channel-specific data.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use futures::future::BoxFuture;
use h3x::{
    codec::{
        BoxReadStream, BoxWriteStream, DecodeExt, EncodeExt, ErasedPeekableBiStream,
        ErasedPeekableUniStream, SinkWriter, StreamReader,
    },
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError},
    stream_id::StreamId,
    varint::VarInt,
};
use snafu::prelude::*;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::constants::CHANNEL_SIGNAL_VALUE;
use crate::conversation::ManageSessionStream;

// ============================================================================
// Type aliases
// ============================================================================

/// Reader half of a routed bidirectional stream.
pub type Ssh3StreamReader = StreamReader<BoxReadStream>;

/// Writer half of a routed bidirectional stream.
pub type Ssh3StreamWriter = SinkWriter<BoxWriteStream>;

/// A routed bidirectional stream after the protocol layer has consumed
/// the signal value and session ID. Raw QUIC streams — consumers wrap
/// in [`StreamReader`]/[`SinkWriter`] as needed.
type RoutedBiStream = (BoxReadStream, BoxWriteStream);

type Registry = Arc<std::sync::Mutex<HashMap<u64, mpsc::Sender<RoutedBiStream>>>>;

/// Closure to open new QUIC bidirectional streams.
///
/// Captured during [`ProductProtocol::init`] to erase the concrete connection
/// type. Returns raw boxed streams — callers wrap them in
/// [`StreamReader`]/[`SinkWriter`] as needed.
pub(crate) type OpenBiFn = Arc<
    dyn Fn() -> BoxFuture<'static, Result<(BoxReadStream, BoxWriteStream), ConnectionError>>
        + Send
        + Sync,
>;

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RegisterError {
    #[snafu(display("conversation already registered for session {session_id}"))]
    AlreadyRegistered { session_id: StreamId },

    #[snafu(display("conversation registry lock poisoned"))]
    RegistryPoisoned,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum HandleError {
    #[snafu(display("conversation stream channel closed"))]
    ChannelClosed,

    #[snafu(display("failed to open bidirectional stream"))]
    OpenBi { source: ConnectionError },

    #[snafu(display("failed to encode channel signal value"))]
    EncodeSignalValue { source: std::io::Error },

    #[snafu(display("failed to encode session ID"))]
    EncodeSessionId { source: std::io::Error },

    #[snafu(display("failed to flush stream header"))]
    Flush { source: std::io::Error },
}

// ============================================================================
// Ssh3Protocol
// ============================================================================

/// SSH3 protocol layer for h3x.
///
/// Routes incoming QUIC bidirectional streams to registered conversations
/// by peeking the channel signal value and session ID.
///
/// Created once per QUIC connection by [`Ssh3ProtocolFactory`] and shared
/// (via `Arc<Protocols>`) across all concurrent streams.
pub struct Ssh3Protocol {
    registry: Registry,
    open_bi: OpenBiFn,
}

impl fmt::Debug for Ssh3Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ssh3Protocol")
            .field(
                "conversations",
                &self.registry.lock().map(|r| r.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl Ssh3Protocol {
    /// Create an `Ssh3Protocol` from a stream-opening closure.
    ///
    /// The closure should open new QUIC bidirectional streams and return
    /// them as boxed trait objects. This is the most flexible constructor —
    /// use it when you have a connection handle that doesn't directly
    /// implement the QUIC traits (e.g., `h3x::connection::Connection<C>`).
    pub fn new(
        open_bi: impl Fn()
            -> BoxFuture<'static, Result<(BoxReadStream, BoxWriteStream), ConnectionError>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
            open_bi: Arc::new(open_bi),
        }
    }

    /// Register a new conversation for the given session ID.
    ///
    /// Returns a [`ConversationHandle`] that receives routed streams and can
    /// open new streams. The handle unregisters the conversation when dropped.
    pub fn register(&self, session_id: StreamId) -> Result<ConversationHandle, RegisterError> {
        use register_error::*;

        let (sender, receiver) = mpsc::channel(16);

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| RegisterError::RegistryPoisoned)?;

        ensure!(
            !registry.contains_key(&session_id.into_inner()),
            AlreadyRegisteredSnafu { session_id }
        );

        registry.insert(session_id.into_inner(), sender);

        Ok(ConversationHandle {
            session_id,
            receiver: tokio::sync::Mutex::new(receiver),
            open_bi: Arc::clone(&self.open_bi),
            registry: Arc::clone(&self.registry),
        })
    }

    async fn accept_bi_inner(
        &self,
        (mut reader, writer): ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        tracing::trace!("ssh3 protocol accept_bi called");

        // Peek the first VarInt to identify SSH3 streams.
        let signal_value: VarInt = match reader.decode_one().await {
            Ok(v) => v,
            Err(_) => return Ok(StreamVerdict::Passed((reader, writer))),
        };

        tracing::trace!(signal_value = %signal_value.into_inner(), "decoded first VarInt");

        if signal_value != CHANNEL_SIGNAL_VALUE {
            return Ok(StreamVerdict::Passed((reader, writer)));
        }

        // SSH3 stream confirmed. Decode session ID to determine routing.
        let session_id: StreamId = match reader.decode_one().await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %snafu::Report::from_error(&e), "failed to decode session ID from SSH3 stream");
                return Ok(StreamVerdict::Accepted);
            }
        };

        tracing::debug!(%session_id, "ssh3 channel stream accepted, routing to conversation");

        // Convert to StreamReader (preserving buffered bytes from the peek
        // operation), then re-box as a BoxReadStream so downstream consumers
        // receive all remaining data (max_message_size, channel_type, etc.).
        let reader: BoxReadStream = Box::pin(reader.into_stream_reader());

        // Lookup and route.
        let sender = {
            let Ok(registry) = self.registry.lock() else {
                tracing::warn!("SSH3 conversation registry lock poisoned");
                return Ok(StreamVerdict::Accepted);
            };
            registry.get(&session_id.into_inner()).cloned()
        };

        match sender {
            Some(sender) => {
                let raw_writer = writer.into_inner();
                if sender.send((reader, raw_writer)).await.is_err() {
                    tracing::debug!(
                        %session_id,
                        "conversation channel closed, dropping SSH3 stream"
                    );
                }
            }
            None => {
                tracing::debug!(
                    %session_id,
                    "no registered conversation for SSH3 stream"
                );
            }
        }

        Ok(StreamVerdict::Accepted)
    }
}

impl Protocol for Ssh3Protocol {
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
        Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
    }

    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
        Box::pin(self.accept_bi_inner(stream))
    }
}

// ============================================================================
// Ssh3ProtocolFactory
// ============================================================================

/// Factory for creating [`Ssh3Protocol`] instances during connection setup.
///
/// Register this as a protocol layer to enable SSH3 stream routing:
///
/// ```ignore
/// server.add_protocol(Ssh3ProtocolFactory);
/// ```
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ssh3ProtocolFactory;

impl<C: quic::DynConnection + ?Sized> ProductProtocol<C> for Ssh3ProtocolFactory {
    type Protocol = Ssh3Protocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        _layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        let conn = conn.clone();
        Box::pin(async move {
            let open_bi: OpenBiFn = Arc::new(move || {
                let conn = conn.clone();
                Box::pin(async move {
                    let (reader, writer) = quic::DynManageStream::open_bi(&*conn).await?;
                    Ok((reader, writer))
                })
            });

            Ok(Ssh3Protocol {
                registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
                open_bi,
            })
        })
    }
}

// ============================================================================
// ConversationHandle
// ============================================================================

/// Handle for a registered conversation.
///
/// Provides stream management for a conversation: accepting streams routed
/// by the protocol layer and opening new streams to the remote peer.
///
/// Implements [`ManageSessionStream`] so it can be used directly with
/// [`Conversation`](crate::conversation::Conversation).
///
/// Dropping the handle automatically unregisters the conversation from the
/// protocol registry.
pub struct ConversationHandle {
    session_id: StreamId,
    receiver: tokio::sync::Mutex<mpsc::Receiver<RoutedBiStream>>,
    open_bi: OpenBiFn,
    registry: Registry,
}

impl ConversationHandle {
    pub fn session_id(&self) -> StreamId {
        self.session_id
    }

    /// Open a raw bidirectional stream with the routing header already written.
    ///
    /// Returns raw boxed streams without codec wrappers. The routing header
    /// (signal value + session ID) is written so the remote protocol layer
    /// routes this stream to the correct conversation.
    pub async fn open_raw_stream(&self) -> Result<(BoxReadStream, BoxWriteStream), HandleError> {
        use handle_error::*;

        let (reader, writer) = (self.open_bi)().await.context(OpenBiSnafu)?;
        let mut codec_writer = SinkWriter::new(writer);

        tracing::trace!(session_id = %self.session_id, "writing channel routing header");

        codec_writer
            .encode_one(CHANNEL_SIGNAL_VALUE)
            .await
            .context(EncodeSignalValueSnafu)?;
        codec_writer
            .encode_one(self.session_id)
            .await
            .context(EncodeSessionIdSnafu)?;
        AsyncWriteExt::flush(&mut codec_writer)
            .await
            .context(FlushSnafu)?;
        let writer = codec_writer.into_inner();

        tracing::trace!(session_id = %self.session_id, "channel routing header written and flushed");

        Ok((reader, writer))
    }

    /// Accept a raw bidirectional stream routed by the protocol layer.
    ///
    /// Returns raw boxed streams without codec wrappers. The protocol layer
    /// has already consumed the signal value and session ID, so the streams
    /// are positioned at the channel-specific data.
    pub async fn accept_raw_stream(&self) -> Result<(BoxReadStream, BoxWriteStream), HandleError> {
        let mut rx = self.receiver.lock().await;
        rx.recv().await.ok_or(HandleError::ChannelClosed)
    }
}

impl fmt::Debug for ConversationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConversationHandle")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Drop for ConversationHandle {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.remove(&self.session_id.into_inner());
        }
    }
}

impl ManageSessionStream for ConversationHandle {
    type StreamReader = Ssh3StreamReader;
    type StreamWriter = Ssh3StreamWriter;
    type Error = HandleError;

    async fn open_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        let (reader, writer) = self.open_raw_stream().await?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    async fn accept_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        let (reader, writer) = self.accept_raw_stream().await?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ConversationHandle is Send + Sync (required for ManageSessionStream usage).
    const _: () = {
        #[allow(dead_code)]
        fn assert_send_sync<T: Send + Sync>() {}
        #[allow(dead_code)]
        fn check() {
            assert_send_sync::<ConversationHandle>();
            assert_send_sync::<Ssh3Protocol>();
        }
    };
}
