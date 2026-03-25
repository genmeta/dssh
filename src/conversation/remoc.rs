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
    codec::{BoxReadStream, BoxWriteStream, SinkWriter, StreamReader},
    dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
    quic::ConnectionError,
    remoc::quic::{ReadStreamClient, ReadStreamServer, WriteStreamClient, WriteStreamServer},
};
use remoc::prelude::Server;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::protocol::{ConversationHandle, HandleError};

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
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        let (ws, wc) = WriteStreamServer::new(writer, 1);

        let mut tasks = self.tasks.lock().expect("task set lock not poisoned");
        while tasks.try_join_next().is_some() {}
        tasks.spawn(
            async move {
                let _ = rs.serve().await;
            }
            .in_current_span(),
        );
        tasks.spawn(
            async move {
                let _ = ws.serve().await;
            }
            .in_current_span(),
        );

        (rc, wc)
    }
}

/// Convert a [`HandleError`] to a [`ConnectionError`] for the remoc RPC boundary.
///
/// This is a lossy conversion at the process boundary — the structured
/// [`HandleError`] is flattened into a [`ConnectionError`] with the full
/// error chain as the reason string.
fn handle_error_to_connection_error(e: HandleError) -> ConnectionError {
    h3x::quic::ApplicationError {
        code: h3x::error::Code::from(h3x::varint::VarInt::from_u32(0)),
        reason: std::borrow::Cow::Owned(snafu::Report::from_error(e).to_string()),
    }
    .into()
}

impl RemoteManageStream for ManageStreamBridge {
    async fn open_stream(&self) -> Result<(ReadStreamClient, WriteStreamClient), ConnectionError> {
        let (reader, writer) = self
            .handle
            .open_raw_stream()
            .await
            .map_err(handle_error_to_connection_error)?;
        Ok(self.serve_pair(reader, writer))
    }

    async fn accept_stream(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), ConnectionError> {
        let (reader, writer) = self
            .handle
            .accept_raw_stream()
            .await
            .map_err(handle_error_to_connection_error)?;
        Ok(self.serve_pair(reader, writer))
    }
}
