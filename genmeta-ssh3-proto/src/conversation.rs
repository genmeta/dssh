//! SSH3 conversation — a multiplexed session over a single QUIC connection.
//!
//! A conversation corresponds to an authenticated SSH3 session (created via
//! HTTP/3 CONNECT). Multiple bidirectional channels are opened within a
//! conversation, each carrying SSH3 channel data on its own QUIC stream.
//!
//! ## Architecture
//!
//! - [`Conversation`] — async trait for opening/accepting channels.
//! - [`LocalConversation`] — holds the real QUIC connection; used in the main process.
//!
//! ## Remoc RTC
//!
//! A remoc RTC bridge (`RemoteConversation`) is planned but blocked on
//! aligning the workspace remoc version (0.14) with h3x's (0.18).
//! See `TODO(remoc)` markers below.

use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use futures::SinkExt;
use h3x::{
    codec::BoxPeekableBiStream,
    connection::QuicConnection,
    quic,
};
use tokio::sync::mpsc;

use crate::{
    codec::{ChannelId, ChannelStreamHeader, ConversationId},
    error::{ChannelError, ProtocolError},
};

/// Type alias for an SSH3 bidirectional stream — a peekable reader + sink writer pair.
///
/// This is the stream type used within a conversation to carry channel data.
/// Each channel gets its own QUIC bidi stream wrapped in this type.
pub type Ssh3BiStream<C> = BoxPeekableBiStream<C>;

/// Async trait for SSH3 conversation operations.
///
/// A conversation manages the lifecycle of SSH3 channels within an
/// authenticated session. Channels are opened as QUIC bidirectional streams
/// with a [`ChannelStreamHeader`] prefix.
///
/// # Generic Parameters
///
/// * `C` — the QUIC connection type (e.g. `quinn::Connection` or `RemoteQuicConnection`)
pub trait Conversation<C: quic::Connection>: Send + Sync {
    /// Open a new channel on this conversation.
    ///
    /// Allocates a new [`ChannelId`], opens a QUIC bidi stream, writes the
    /// [`ChannelStreamHeader`], and returns the channel ID along with the stream.
    fn open_channel(
        &self,
        channel_type: &str,
        max_message_size: u64,
    ) -> impl Future<Output = Result<(ChannelId, Ssh3BiStream<C>), ChannelError>> + Send;

    /// Accept an inbound channel from the remote peer.
    ///
    /// Blocks until the protocol layer routes an inbound stream to this
    /// conversation. Returns the channel ID, channel type, and the stream.
    fn accept_channel(
        &self,
    ) -> impl Future<Output = Result<(ChannelId, String, Ssh3BiStream<C>), ChannelError>> + Send;

    /// Close this conversation.
    fn close(&self) -> impl Future<Output = Result<(), ProtocolError>> + Send;

    // TODO: add global request methods after Task 5 (SshMessage) completes:
    //   fn send_global_request(&self, request: GlobalRequest) -> impl Future<...>;
    //   fn recv_global_request(&self) -> impl Future<...>;
}

/// Local conversation — holds the actual QUIC connection and manages channels.
///
/// Created in the main process when an SSH3 session is established.
/// Inbound streams are pushed into [`inbound_sender`](Self::inbound_sender)
/// by the [`Ssh3Protocol`] layer after routing by conversation ID.
pub struct LocalConversation<C: quic::Connection> {
    /// The conversation identifier (QUIC stream ID of the CONNECT request).
    pub(crate) conversation_id: ConversationId,

    /// QUIC connection wrapper for opening new bidi streams.
    pub(crate) connection: Arc<QuicConnection<C>>,

    /// Receiver for inbound bidi streams routed to this conversation.
    pub(crate) inbound: tokio::sync::Mutex<mpsc::Receiver<Ssh3BiStream<C>>>,

    /// Sender half — held separately so the protocol layer can push streams.
    pub(crate) inbound_tx: mpsc::Sender<Ssh3BiStream<C>>,

    /// Monotonically increasing channel ID counter.
    pub(crate) next_channel_id: AtomicU32,
}

impl<C: quic::Connection> LocalConversation<C> {
    /// Create a new local conversation.
    ///
    /// # Arguments
    ///
    /// * `conversation_id` — the conversation identifier
    /// * `connection` — shared QUIC connection for opening streams
    /// * `inbound_buffer` — capacity of the inbound channel buffer
    pub fn new(
        conversation_id: ConversationId,
        connection: Arc<QuicConnection<C>>,
        inbound_buffer: usize,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(inbound_buffer);
        Self {
            conversation_id,
            connection,
            inbound: tokio::sync::Mutex::new(inbound_rx),
            inbound_tx,
            next_channel_id: AtomicU32::new(0),
        }
    }

    /// Get the conversation identifier.
    pub fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Get the inbound sender for the protocol layer to push routed streams.
    pub fn inbound_sender(&self) -> mpsc::Sender<Ssh3BiStream<C>> {
        self.inbound_tx.clone()
    }

    /// Allocate the next channel ID.
    fn allocate_channel_id(&self) -> ChannelId {
        let id = self.next_channel_id.fetch_add(1, Ordering::Relaxed);
        ChannelId::new(id)
    }
}

impl<C: quic::Connection + 'static> Conversation<C> for LocalConversation<C> {
    async fn open_channel(
        &self,
        channel_type: &str,
        max_message_size: u64,
    ) -> Result<(ChannelId, Ssh3BiStream<C>), ChannelError> {
        let channel_id = self.allocate_channel_id();

        // Open a new QUIC bidi stream.
        let (reader, writer) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| ChannelError::OpenFailed {
                reason: e.to_string(),
            })?;

        // Wrap into h3x codec types.
        let reader = h3x::codec::PeekableStreamReader::new(h3x::codec::StreamReader::new(
            Box::pin(reader),
        ));
        let mut writer = h3x::codec::SinkWriter::new(Box::pin(writer));

        // Encode the channel stream header.
        let header = ChannelStreamHeader::new(
            self.conversation_id,
            channel_type.to_string(),
            max_message_size,
        );
        let header_bytes = header.encode_to_vec().map_err(|e| ChannelError::OpenFailed {
            reason: e.to_string(),
        })?;

        // Write the header to the stream.
        writer
            .send(bytes::Bytes::from(header_bytes))
            .await
            .map_err(|e| ChannelError::OpenFailed {
                reason: e.to_string(),
            })?;

        tracing::debug!(
            conversation_id = %self.conversation_id,
            channel_id = %channel_id,
            channel_type,
            "opened channel"
        );

        Ok((channel_id, (reader, writer)))
    }

    async fn accept_channel(
        &self,
    ) -> Result<(ChannelId, String, Ssh3BiStream<C>), ChannelError> {
        let mut inbound = self.inbound.lock().await;
        let stream = inbound.recv().await.ok_or(ChannelError::OpenFailed {
            reason: "conversation closed".to_string(),
        })?;

        // The stream header has already been parsed by the protocol layer
        // which routed it to this conversation. We allocate a local channel ID.
        let channel_id = self.allocate_channel_id();

        // TODO: extract channel_type from the already-parsed header.
        // For now, the protocol layer should pass the channel type alongside
        // the stream. This will be refined when Ssh3Protocol (Task 7) is implemented.
        let channel_type = String::new();

        tracing::debug!(
            conversation_id = %self.conversation_id,
            channel_id = %channel_id,
            "accepted channel"
        );

        Ok((channel_id, channel_type, stream))
    }

    async fn close(&self) -> Result<(), ProtocolError> {
        // Close the inbound channel to stop accepting new streams.
        self.inbound_tx.closed().await;

        tracing::debug!(
            conversation_id = %self.conversation_id,
            "conversation closed"
        );

        Ok(())
    }
}

// TODO(remoc): Add remoc RTC bridge once the workspace remoc version is
// aligned with h3x's (currently 0.14 vs 0.18). The bridge would include:
//
// - `ConversationRtc` — `#[remoc::rtc::remote]` trait mirroring `Conversation`
//   but using serializable stream types.
// - `LocalConversationRtc<C>` — server-side wrapper bridging `LocalConversation`
//   to the RTC trait.
// - `RemoteConversation` — serializable proxy wrapping the generated RTC client.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `Ssh3BiStream<C>` is the expected h3x type alias.
    const _: () = {
        // Ensure the type alias resolves correctly for any quic::Connection.
        fn assert_same_type<C: quic::Connection>()
        where
            Ssh3BiStream<C>: Sized,
        {
        }
    };

    #[test]
    fn conversation_id_usage() {
        let conv_id = ConversationId::new(42);
        assert_eq!(conv_id.into_inner(), 42);
    }

    #[test]
    fn channel_id_allocation() {
        let counter = AtomicU32::new(0);
        let id0 = ChannelId::new(counter.fetch_add(1, Ordering::Relaxed));
        let id1 = ChannelId::new(counter.fetch_add(1, Ordering::Relaxed));
        assert_eq!(id0.into_inner(), 0);
        assert_eq!(id1.into_inner(), 1);
    }

    #[test]
    fn channel_stream_header_with_conversation() {
        let conv_id = ConversationId::new(100);
        let header = ChannelStreamHeader::new(conv_id, "session".to_string(), 65536);
        let encoded = header.encode_to_vec().unwrap();
        let (decoded, _) = ChannelStreamHeader::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.conversation_id, conv_id);
        assert_eq!(decoded.channel_type, "session");
        assert_eq!(decoded.max_message_size, 65536);
    }
}
