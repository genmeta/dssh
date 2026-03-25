//! Remoc bridge for [`ManageSessionStream`](super::ManageSessionStream).
//!
//! Exposes a conversation's stream management over process boundaries via
//! [remoc](::remoc) RPC. The gateway process wraps a
//! [`ConversationHandle`](crate::protocol::ConversationHandle) in a
//! [`ManageStreamBridge`] and serves the generated
//! [`RemoteManageStreamServerShared`]; the child process receives a
//! [`RemoteManageStreamClient`] and uses it as a `ManageSessionStream`
//! implementation for its local [`Conversation`](super::Conversation).

use std::sync::Mutex;

use h3x::{
    codec::{BoxReadStream, BoxWriteStream, EncodeExt, SinkWriter, StreamReader},
    dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
    quic::ConnectionError,
    remoc::quic::{
        ReadStreamClient, ReadStreamServer, WriteStreamClient, WriteStreamServer,
    },
};
use remoc::rtc::Server;
use tokio::{io::AsyncWriteExt, task::JoinSet};

use crate::constants::CHANNEL_SIGNAL_VALUE;
use crate::protocol::ConversationHandle;

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

/// Remoc RPC counterpart of [`ManageSessionStream`](super::ManageSessionStream).
///
/// The `#[remoc::rtc::remote]` macro generates [`RemoteManageStreamClient`]
/// (for the child process) and server wrapper types (for the gateway).
#[remoc::rtc::remote]
pub trait RemoteManageStream: Send + Sync {
    async fn open_stream(&self) -> Result<(ReadStreamClient, WriteStreamClient), ConnectionError>;

    async fn accept_stream(&self)
    -> Result<(ReadStreamClient, WriteStreamClient), ConnectionError>;
}

// ---------------------------------------------------------------------------
// Client → ManageSessionStream
// ---------------------------------------------------------------------------

impl super::ManageSessionStream for RemoteManageStreamClient {
    type StreamReader = StreamReader<BoxDynQuicStreamReader>;
    type StreamWriter = SinkWriter<BoxDynQuicStreamWriter>;
    type Error = ConnectionError;

    async fn open_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        RemoteManageStream::open_stream(self)
            .await
            .map(into_codec_pair)
    }

    async fn accept_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        RemoteManageStream::accept_stream(self)
            .await
            .map(into_codec_pair)
    }
}

fn into_codec_pair(
    (reader, writer): (ReadStreamClient, WriteStreamClient),
) -> (
    StreamReader<BoxDynQuicStreamReader>,
    SinkWriter<BoxDynQuicStreamWriter>,
) {
    let reader = StreamReader::new(reader.into_boxed_quic());
    let writer = SinkWriter::new(writer.into_boxed_quic());
    (reader, writer)
}

// ---------------------------------------------------------------------------
// Server — bridge from ConversationHandle to RPC
// ---------------------------------------------------------------------------

/// Bridges a local [`ConversationHandle`] to the [`RemoteManageStream`] RPC
/// trait so that a child process can open/accept QUIC streams remotely.
///
/// Each call to `open_stream` / `accept_stream` spawns background tasks that
/// serve individual QUIC streams over remoc. These tasks are reaped lazily.
pub struct ManageStreamBridge {
    handle: ConversationHandle,
    tasks: Mutex<JoinSet<()>>,
}

impl ManageStreamBridge {
    pub fn new(handle: ConversationHandle) -> Self {
        Self {
            handle,
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    /// Serve a raw QUIC stream pair via remoc, returning serializable clients.
    fn serve_pair(
        &self,
        reader: BoxReadStream,
        writer: BoxWriteStream,
    ) -> (ReadStreamClient, WriteStreamClient) {
        let (read_server, rc) = ReadStreamServer::new(reader, 1);
        let (write_server, wc) = WriteStreamServer::new(writer, 1);

        let mut tasks = self.tasks.lock().expect("task set lock not poisoned");
        // Drain completed tasks to avoid unbounded growth.
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _ = read_server.serve().await;
        });
        tasks.spawn(async move {
            let _ = write_server.serve().await;
        });

        (rc, wc)
    }
}

impl RemoteManageStream for ManageStreamBridge {
    async fn open_stream(&self) -> Result<(ReadStreamClient, WriteStreamClient), ConnectionError> {
        // Open a raw QUIC bidirectional stream.
        let (reader, writer) = (self.handle.open_bi)().await?;

        // Write the routing header (signal value + session ID) so that the
        // protocol layer on the receiving end routes this stream correctly.
        let mut codec_writer = SinkWriter::new(writer);
        codec_writer
            .encode_one(CHANNEL_SIGNAL_VALUE)
            .await
            .map_err(|e| connection_error(&e))?;
        codec_writer
            .encode_one(self.handle.session_id)
            .await
            .map_err(|e| connection_error(&e))?;
        AsyncWriteExt::flush(&mut codec_writer)
            .await
            .map_err(|e| connection_error(&e))?;
        let writer = codec_writer.into_inner();

        Ok(self.serve_pair(reader, writer))
    }

    async fn accept_stream(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), ConnectionError> {
        let (reader, writer) = self
            .handle
            .receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(channel_closed)?;

        Ok(self.serve_pair(reader, writer))
    }
}

/// Construct a [`ConnectionError`] from an I/O error.
fn connection_error(e: &std::io::Error) -> ConnectionError {
    h3x::quic::ApplicationError {
        code: h3x::error::Code::from(h3x::varint::VarInt::from_u32(0)),
        reason: std::borrow::Cow::Owned(e.to_string()),
    }
    .into()
}

/// Construct a [`ConnectionError`] indicating the channel is closed.
fn channel_closed() -> ConnectionError {
    h3x::quic::ApplicationError {
        code: h3x::error::Code::from(h3x::varint::VarInt::from_u32(0)),
        reason: std::borrow::Cow::Borrowed("conversation stream channel closed"),
    }
    .into()
}
