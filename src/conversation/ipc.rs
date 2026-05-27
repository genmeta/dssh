//! IPC bridge for [`ManageSessionStream`](super::ManageSessionStream).
//!
//! Replaces the remoc-serialized stream proxy ([`super::remoc`]) with direct
//! FD passing over a [`MuxChannel`]. Stream data travels through Unix
//! socketpairs instead of being serialized through remoc, eliminating the
//! per-byte serialization overhead.
//!
//! # Architecture
//!
//! The gateway process wraps a [`ManageSessionStream`](super::ManageSessionStream)
//! implementation (for example a WebTransport-backed stream manager) in an
//! [`IpcManageStreamAdapter`] and
//! serves the generated [`IpcManageSessionStreamServerShared`]. Each
//! `open_stream` / `accept_stream` call:
//! 1. Opens a real bidirectional stream through the wrapped manager.
//! 2. Creates a Unix socketpair.
//! 3. Queues the client-side FD through the [`FdSender`].
//! 4. Spawns bridge tasks forwarding data between the managed stream and the
//!    server-side socketpair half.
//! 5. Returns the FD-registry batch ID over RPC.
//!
//! The child process receives an [`IpcManageSessionStreamClient`] and wraps it
//! in [`IpcManageStreamHandle`], which implements [`ManageSessionStream`]:
//! 1. Calls the RPC method to get the FD-registry batch ID.
//! 2. Retrieves the socketpair FD from the [`FdRegistry`].
//! 3. Splits it into `(OwnedReadHalf, OwnedWriteHalf)`.

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use h3x::{
    ipc::transport::{FdRegistry, FdSender, WaitFdsError},
    quic::ConnectionError,
    varint::VarInt,
};
use snafu::{OptionExt, Snafu};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
};
use tracing::Instrument;

fn unix_stream_from_std(stream: std::os::unix::net::UnixStream) -> std::io::Result<UnixStream> {
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream)
}

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

/// Remoc RPC counterpart of [`ManageSessionStream`](super::ManageSessionStream)
/// using FD passing for stream data.
///
/// Each method returns a [`VarInt`] — the FD-registry batch ID. The caller
/// passes it to [`FdRegistry::wait_fds`] to retrieve a single `OwnedFd` for a
/// bidirectional Unix socketpair.
#[remoc::rtc::remote]
pub trait IpcManageSessionStream: Send + Sync {
    async fn open_stream(&self) -> Result<VarInt, ConnectionError>;
    async fn accept_stream(&self) -> Result<VarInt, ConnectionError>;
}

// ---------------------------------------------------------------------------
// Client → ManageSessionStream
// ---------------------------------------------------------------------------

/// Client-side handle wrapping an [`IpcManageSessionStreamClient`] and
/// [`FdRegistry`], implementing [`ManageSessionStream`].
///
/// Each `open_stream` / `accept_stream` call:
/// 1. Calls the RPC to get a FD-registry batch ID.
/// 2. Waits for FDs from the registry.
/// 3. Converts the `OwnedFd` to a tokio `UnixStream` and splits it.
pub struct IpcManageStreamHandle {
    rpc: IpcManageSessionStreamClient,
    fd_registry: FdRegistry,
}

/// Error from [`IpcManageStreamHandle`] operations.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IpcManageStreamError {
    #[snafu(display("manage stream RPC failed"))]
    Rpc { source: ConnectionError },
    #[snafu(display("failed to receive stream FD"))]
    ReceiveFd { source: WaitFdsError },
    #[snafu(display("expected 1 FD, got {actual}"))]
    UnexpectedFdCount { actual: usize },
    #[snafu(display("failed to convert FD to UnixStream"))]
    FromFd { source: std::io::Error },
}

impl IpcManageStreamHandle {
    pub fn new(rpc: IpcManageSessionStreamClient, fd_registry: FdRegistry) -> Self {
        Self { rpc, fd_registry }
    }

    async fn resolve_stream(
        &self,
        fd_id: VarInt,
    ) -> Result<(OwnedReadHalf, OwnedWriteHalf), IpcManageStreamError> {
        use ipc_manage_stream_error::*;
        use snafu::ResultExt;

        let fds = self
            .fd_registry
            .wait_fds(fd_id)
            .await
            .context(ReceiveFdSnafu)?;
        let fd = fds
            .into_iter()
            .next()
            .context(UnexpectedFdCountSnafu { actual: 0_usize })?;
        let stream =
            unix_stream_from_std(std::os::unix::net::UnixStream::from(fd)).context(FromFdSnafu)?;
        Ok(stream.into_split())
    }
}

impl super::ManageSessionStream for IpcManageStreamHandle {
    type StreamReader = OwnedReadHalf;
    type StreamWriter = OwnedWriteHalf;
    type Error = IpcManageStreamError;

    async fn open_stream(&self) -> Result<(OwnedReadHalf, OwnedWriteHalf), IpcManageStreamError> {
        use ipc_manage_stream_error::*;
        use snafu::ResultExt;

        let fd_id = IpcManageSessionStream::open_stream(&self.rpc)
            .await
            .context(RpcSnafu)?;
        self.resolve_stream(fd_id).await
    }

    async fn accept_stream(&self) -> Result<(OwnedReadHalf, OwnedWriteHalf), IpcManageStreamError> {
        use ipc_manage_stream_error::*;
        use snafu::ResultExt;

        let fd_id = IpcManageSessionStream::accept_stream(&self.rpc)
            .await
            .context(RpcSnafu)?;
        self.resolve_stream(fd_id).await
    }
}

// ---------------------------------------------------------------------------
// Server: IpcManageStreamAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter bridging a [`ManageSessionStream`](super::ManageSessionStream) to the
/// [`IpcManageSessionStream`] RPC trait.
///
/// Each call opens a real managed stream, creates a Unix socketpair, spawns
/// bridge tasks, and queues the client-side FD through the [`FdSender`].
///
/// Bridge tasks are spawned via [`tokio::spawn`] so they outlive this
/// adapter. They terminate naturally when the Unix socketpair is closed
/// (i.e. when the child process drops its half). This is important because
/// the adapter may be dropped (via the remoc `ServerShared` lifecycle)
/// before the bridge has finished flushing final data — such as SSH
/// exit-status, EOF and Close messages — to the managed stream.
pub struct IpcManageStreamAdapter<M> {
    manage_stream: M,
    fd_sender: FdSender,
}

impl<M> IpcManageStreamAdapter<M> {
    pub fn new(manage_stream: M, fd_sender: FdSender) -> Self {
        Self {
            manage_stream,
            fd_sender,
        }
    }

    fn bridge_and_queue<R, W>(&self, reader: R, writer: W) -> Result<VarInt, ConnectionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (srv, cli) =
            std::os::unix::net::UnixStream::pair().map_err(|e| to_conn_error(e, "socketpair"))?;
        cli.set_nonblocking(true)
            .map_err(|e| to_conn_error(e, "set_nonblocking"))?;

        let fd_id = self
            .fd_sender
            .queue_fds(vec![cli.into()].into())
            .map_err(|e| to_conn_error(e, "queue_fds"))?;

        let srv = unix_stream_from_std(srv).map_err(|e| to_conn_error(e, "from_std"))?;
        let (srv_read, srv_write) = srv.into_split();

        // Spawn bridge tasks independently so they are NOT aborted when this
        // adapter is dropped. The tasks will terminate on their own once the
        // Unix socketpair closes (child process exit / fd drop).
        tokio::spawn(bridge_reader_to_unix(reader, srv_write).in_current_span());
        tokio::spawn(bridge_unix_to_writer(srv_read, writer).in_current_span());

        Ok(fd_id)
    }
}

impl<M> IpcManageSessionStream for IpcManageStreamAdapter<M>
where
    M: super::ManageSessionStream + 'static,
    M::StreamReader: AsyncRead + Unpin + Send + 'static,
    M::StreamWriter: AsyncWrite + Unpin + Send + 'static,
    M::Error: Send + Sync + 'static,
{
    async fn open_stream(&self) -> Result<VarInt, ConnectionError> {
        let (reader, writer) = self
            .manage_stream
            .open_stream()
            .await
            .map_err(manage_stream_error_to_connection_error)?;
        self.bridge_and_queue(reader, writer)
    }

    async fn accept_stream(&self) -> Result<VarInt, ConnectionError> {
        let (reader, writer) = self
            .manage_stream
            .accept_stream()
            .await
            .map_err(manage_stream_error_to_connection_error)?;
        self.bridge_and_queue(reader, writer)
    }
}

// ---------------------------------------------------------------------------
// Bridge helpers: QUIC stream ↔ Unix socketpair
// ---------------------------------------------------------------------------

/// Forward bytes from an async reader to a Unix socket write half.
pub async fn bridge_reader_to_unix<R>(mut reader: R, mut writer: OwnedWriteHalf)
where
    R: AsyncRead + Unpin,
{
    let _ = tokio::io::copy(&mut reader, &mut writer).await;
    let _ = writer.shutdown().await;
}

/// Forward bytes from a Unix socket read half to an async writer.
pub async fn bridge_unix_to_writer<W>(mut reader: OwnedReadHalf, mut writer: W)
where
    W: AsyncWrite + Unpin,
{
    let _ = tokio::io::copy(&mut reader, &mut writer).await;
    let _ = writer.shutdown().await;
}

// ---------------------------------------------------------------------------
// Control stream bridge helpers (used by sshd.rs)
// ---------------------------------------------------------------------------

/// Forward data from an h3x message read stream to a Unix socket write half.
///
/// Used for the SSH3 control channel: QUIC CONNECT upgrade data → child process.
pub async fn bridge_message_reader_to_unix(
    mut reader: impl futures::Stream<Item = Result<Bytes, impl std::error::Error>> + Unpin,
    mut writer: OwnedWriteHalf,
) {
    while let Some(Ok(chunk)) = reader.next().await {
        if writer.write_all(&chunk).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

/// Forward data from a Unix socket read half to an h3x message write sink.
///
/// Used for the SSH3 control channel: child process → QUIC CONNECT upgrade data.
pub async fn bridge_unix_to_message_writer(
    mut reader: OwnedReadHalf,
    mut writer: impl futures::Sink<Bytes, Error = impl std::error::Error> + Unpin,
) {
    use tokio::io::AsyncReadExt;

    let mut buf = BytesMut::with_capacity(8192);
    loop {
        buf.reserve(8192);
        match reader.read_buf(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if writer.send(buf.split().freeze()).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = writer.close().await;
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn to_conn_error(err: impl std::fmt::Display, context: &str) -> ConnectionError {
    tracing::warn!(%err, context, "ipc manage stream error");
    h3x::quic::ApplicationError {
        code: h3x::error::Code::from(VarInt::from_u32(0)),
        reason: std::borrow::Cow::Owned(format!("ipc {context}: {err}")),
    }
    .into()
}

fn manage_stream_error_to_connection_error<E>(error: E) -> ConnectionError
where
    E: std::error::Error + Send + Sync + 'static,
{
    h3x::quic::ApplicationError {
        code: h3x::error::Code::from(VarInt::from_u32(0)),
        reason: std::borrow::Cow::Owned(snafu::Report::from_error(&error).to_string()),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use h3x::{ipc::transport::MuxChannel, varint::VarInt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{IpcManageSessionStream, IpcManageStreamAdapter, unix_stream_from_std};
    use crate::conversation::ManageSessionStream;

    #[derive(Clone, Debug)]
    struct MockManageStream {
        open_calls: Arc<AtomicUsize>,
    }

    impl ManageSessionStream for MockManageStream {
        type StreamReader = tokio::io::Empty;
        type StreamWriter = tokio::io::Sink;
        type Error = std::io::Error;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.open_calls.fetch_add(1, Ordering::SeqCst);
            Ok((tokio::io::empty(), tokio::io::sink()))
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            Ok((tokio::io::empty(), tokio::io::sink()))
        }
    }

    #[tokio::test]
    async fn ipc_adapter_accepts_generic_manage_session_stream() {
        let open_calls = Arc::new(AtomicUsize::new(0));
        let manage_stream = MockManageStream {
            open_calls: open_calls.clone(),
        };
        let (channel, _remote_fd) = MuxChannel::create_pair().expect("mux channel");
        let (sink, _stream) = channel.split().expect("split mux channel");
        let adapter = IpcManageStreamAdapter::new(manage_stream, sink.fd_sender());

        let fd_id = IpcManageSessionStream::open_stream(&adapter)
            .await
            .expect("open stream through adapter");

        assert_eq!(fd_id, VarInt::from_u32(0));
        assert_eq!(open_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unix_stream_from_std_accepts_default_blocking_socketpair() {
        let (left, right) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let mut left = unix_stream_from_std(left).expect("left stream");
        let mut right = unix_stream_from_std(right).expect("right stream");

        left.write_all(b"x").await.expect("write");
        let mut buf = [0_u8; 1];
        right.read_exact(&mut buf).await.expect("read");

        assert_eq!(buf, [b'x']);
    }
}
