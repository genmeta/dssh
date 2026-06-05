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
//! 3. Delivers the client-side FD through the [`FdTransfer`].
//! 4. Spawns bridge tasks forwarding data between the managed stream and the
//!    server-side socketpair half.
//! 5. Returns the FD-registry batch ID over RPC.
//!
//! The child process receives an [`IpcManageSessionStreamClient`] and wraps it
//! in [`IpcManageStreamHandle`], which implements [`ManageSessionStream`]:
//! 1. Reserves a receiver-chosen FD transfer ID.
//! 2. Calls the RPC method with that ID while concurrently receiving the FD.
//! 3. Splits it into `(OwnedReadHalf, OwnedWriteHalf)`.

use std::{
    future::{Future, IntoFuture},
    sync::Mutex,
};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use h3x::{
    ipc::transport::{FdDelivery, FdTransfer, WaitFdsError},
    quic::ConnectionError,
    varint::VarInt,
};
use snafu::Snafu;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
};
use tokio_util::task::AbortOnDropHandle;
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
/// Each method receives a receiver-chosen FD transfer ID and echoes it after
/// the FD delivery is queued to the local mux writer FIFO.
#[remoc::rtc::remote]
pub trait IpcManageSessionStream: Send + Sync {
    async fn open_stream(&self, fd_id: VarInt) -> Result<VarInt, ConnectionError>;
    async fn accept_stream(&self, fd_id: VarInt) -> Result<VarInt, ConnectionError>;
}

// ---------------------------------------------------------------------------
// Client → ManageSessionStream
// ---------------------------------------------------------------------------

/// Client-side handle wrapping an [`IpcManageSessionStreamClient`] and
/// [`FdTransfer`], implementing [`ManageSessionStream`].
///
/// Each `open_stream` / `accept_stream` call:
/// 1. Reserves a receiver-chosen FD transfer ID.
/// 2. Calls the RPC with that ID while receiving the FD.
/// 3. Converts the `OwnedFd` to a tokio `UnixStream` and splits it.
pub struct IpcManageStreamHandle {
    rpc: IpcManageSessionStreamClient,
    fd_transfer: FdTransfer,
}

/// Error from [`IpcManageStreamHandle`] operations.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum IpcManageStreamError {
    #[snafu(display("manage stream RPC failed"))]
    Rpc { source: ConnectionError },
    #[snafu(display("failed to receive stream FD"))]
    ReceiveFd { source: WaitFdsError },
    #[snafu(display("unexpected stream fd batch size"))]
    UnexpectedFdCount {
        source: h3x::ipc::transport::TakeFdsError,
    },
    #[snafu(display("peer responded with fd id {actual}, expected {expected}"))]
    FdIdMismatch { expected: VarInt, actual: VarInt },
    #[snafu(display("failed to convert FD to UnixStream"))]
    FromFd { source: std::io::Error },
}

impl IpcManageStreamHandle {
    pub fn new(rpc: IpcManageSessionStreamClient, fd_transfer: FdTransfer) -> Self {
        Self { rpc, fd_transfer }
    }

    async fn resolve_stream(
        &self,
        rpc: impl std::future::Future<Output = Result<VarInt, ConnectionError>>,
        receiver: h3x::ipc::transport::FdReceiver,
    ) -> Result<(OwnedReadHalf, OwnedWriteHalf), IpcManageStreamError> {
        use ipc_manage_stream_error::*;
        use snafu::ResultExt;

        let expected = receiver.id();
        let receive = receiver.into_future();
        tokio::pin!(rpc);
        tokio::pin!(receive);
        let (actual, received) = tokio::select! {
            biased;
            receive_result = &mut receive => {
                let received = receive_result.context(ReceiveFdSnafu)?;
                let actual = rpc.await.context(RpcSnafu)?;
                (actual, received)
            }
            rpc_result = &mut rpc => {
                let actual = rpc_result.context(RpcSnafu)?;
                let received = receive.await.context(ReceiveFdSnafu)?;
                (actual, received)
            }
        };
        snafu::ensure!(actual == expected, FdIdMismatchSnafu { expected, actual });
        let fd = received.into_one().context(UnexpectedFdCountSnafu)?;
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
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        self.resolve_stream(
            IpcManageSessionStream::open_stream(&self.rpc, fd_id),
            receiver,
        )
        .await
    }

    async fn accept_stream(&self) -> Result<(OwnedReadHalf, OwnedWriteHalf), IpcManageStreamError> {
        let receiver = self.fd_transfer.receive();
        let fd_id = receiver.id();
        self.resolve_stream(
            IpcManageSessionStream::accept_stream(&self.rpc, fd_id),
            receiver,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Server: IpcManageStreamAdapter
// ---------------------------------------------------------------------------

/// Server-side adapter bridging a [`ManageSessionStream`](super::ManageSessionStream) to the
/// [`IpcManageSessionStream`] RPC trait.
///
/// Each call opens a real managed stream, creates a Unix socketpair, spawns
/// bridge tasks, and delivers the client-side FD through the [`FdTransfer`].
///
/// Bridge tasks are owned by this adapter through [`AbortOnDropHandle`]. They
/// may outlive the individual RPC call that created them, but dropping the
/// adapter also drops the bridge task handles so a remoc server lifecycle
/// teardown cannot leak stream-forwarding tasks.
pub struct IpcManageStreamAdapter<M> {
    manage_stream: M,
    fd_transfer: FdTransfer,
    bridge_tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
}

impl<M> IpcManageStreamAdapter<M> {
    pub fn new(manage_stream: M, fd_transfer: FdTransfer) -> Self {
        Self {
            manage_stream,
            fd_transfer,
            bridge_tasks: Mutex::new(Vec::new()),
        }
    }

    fn spawn_bridge_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let handle = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));
        self.bridge_tasks
            .lock()
            .expect("bridge task registry should not be poisoned")
            .push(handle);
    }

    async fn bridge_and_deliver<R, W>(
        &self,
        delivery: FdDelivery,
        reader: R,
        mut writer: W,
        fd_id: VarInt,
    ) -> Result<VarInt, ConnectionError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (srv, cli) =
            std::os::unix::net::UnixStream::pair().map_err(|e| to_conn_error(e, "socketpair"))?;
        cli.set_nonblocking(true)
            .map_err(|e| to_conn_error(e, "set_nonblocking"))?;
        let srv = unix_stream_from_std(srv).map_err(|e| to_conn_error(e, "from_std"))?;
        let (srv_read, srv_write) = srv.into_split();

        let mut fds = h3x::ipc::transport::FdVec::new();
        fds.push(cli.into());
        if let Err(error) = delivery.deliver(fds).await {
            let _ = writer.shutdown().await;
            return Err(to_conn_error(error, "deliver fds"));
        }

        self.spawn_bridge_task(bridge_reader_to_unix(reader, srv_write));
        self.spawn_bridge_task(bridge_unix_to_writer(srv_read, writer));

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
    async fn open_stream(&self, fd_id: VarInt) -> Result<VarInt, ConnectionError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let (reader, writer) = self
            .manage_stream
            .open_stream()
            .await
            .map_err(manage_stream_error_to_connection_error)?;
        self.bridge_and_deliver(delivery, reader, writer, fd_id)
            .await
    }

    async fn accept_stream(&self, fd_id: VarInt) -> Result<VarInt, ConnectionError> {
        let delivery = self.fd_transfer.delivery(fd_id);
        let (reader, writer) = self
            .manage_stream
            .accept_stream()
            .await
            .map_err(manage_stream_error_to_connection_error)?;
        self.bridge_and_deliver(delivery, reader, writer, fd_id)
            .await
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

fn to_conn_error(err: impl std::error::Error, context: &str) -> ConnectionError {
    tracing::warn!(error = %snafu::Report::from_error(&err), context, "ipc manage stream error");
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
    use std::{
        future::IntoFuture,
        os::fd::OwnedFd,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use h3x::ipc::transport::MuxChannel;
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

    #[derive(Clone, Debug, Default)]
    struct BlockingManageStream {
        held_peers: Arc<Mutex<Vec<tokio::io::DuplexStream>>>,
    }

    impl ManageSessionStream for BlockingManageStream {
        type StreamReader = tokio::io::DuplexStream;
        type StreamWriter = tokio::io::DuplexStream;
        type Error = std::io::Error;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            let (reader, reader_peer) = tokio::io::duplex(64);
            let (writer_peer, writer) = tokio::io::duplex(64);
            let mut held_peers = self.held_peers.lock().expect("held peer lock");
            held_peers.push(reader_peer);
            held_peers.push(writer_peer);
            Ok((reader, writer))
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.open_stream().await
        }
    }

    fn mux_pair() -> (MuxChannel, MuxChannel) {
        let (left, right) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let left = MuxChannel::from_fd(OwnedFd::from(left)).expect("left mux channel");
        let right = MuxChannel::from_fd(OwnedFd::from(right)).expect("right mux channel");
        (left, right)
    }

    #[tokio::test]
    async fn ipc_adapter_accepts_generic_manage_session_stream() {
        let open_calls = Arc::new(AtomicUsize::new(0));
        let manage_stream = MockManageStream {
            open_calls: open_calls.clone(),
        };
        let (server_mux, client_mux) = mux_pair();
        let (server_sink, server_stream) = server_mux.split().expect("server mux split");
        let server_fd_transfer = server_stream.fd_transfer(server_sink.fd_sender());
        let (client_sink, client_stream) = client_mux.split().expect("client mux split");
        let client_fd_transfer = client_stream.fd_transfer(client_sink.fd_sender());
        let adapter = IpcManageStreamAdapter::new(manage_stream, server_fd_transfer);
        let receiver = client_fd_transfer.receive();
        let fd_id = receiver.id();

        let (returned, received) = {
            let call = IpcManageSessionStream::open_stream(&adapter, fd_id);
            let receive = receiver.into_future();
            tokio::pin!(call);
            tokio::pin!(receive);
            tokio::join!(call, receive)
        };

        assert_eq!(returned.expect("open stream through adapter"), fd_id);
        assert_eq!(received.expect("receive delivered fd").len(), 1);
        assert_eq!(open_calls.load(Ordering::SeqCst), 1);
        drop((server_sink, server_stream, client_sink, client_stream));
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

    #[tokio::test]
    async fn dropping_ipc_adapter_aborts_owned_bridge_tasks() {
        let (server_mux, client_mux) = mux_pair();
        let (server_sink, server_stream) = server_mux.split().expect("server mux split");
        let server_fd_transfer = server_stream.fd_transfer(server_sink.fd_sender());
        let (client_sink, client_stream) = client_mux.split().expect("client mux split");
        let client_fd_transfer = client_stream.fd_transfer(client_sink.fd_sender());

        let manage_stream = BlockingManageStream::default();
        let held_peers = manage_stream.held_peers.clone();
        let adapter = IpcManageStreamAdapter::new(manage_stream, server_fd_transfer);
        let receiver = client_fd_transfer.receive();
        let fd_id = receiver.id();
        let (returned, received) = {
            let call = IpcManageSessionStream::open_stream(&adapter, fd_id);
            let receive = receiver.into_future();
            tokio::pin!(call);
            tokio::pin!(receive);
            tokio::join!(call, receive)
        };
        assert_eq!(returned.expect("open stream"), fd_id);
        let fd = received
            .expect("receive delivered fd")
            .into_one()
            .expect("one stream fd");
        let mut stream =
            unix_stream_from_std(std::os::unix::net::UnixStream::from(fd)).expect("tokio stream");

        let mut buf = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf))
                .await
                .is_err(),
            "stream peer should remain open while adapter owns bridge tasks",
        );

        drop(adapter);
        assert_eq!(
            held_peers.lock().expect("held peer lock").len(),
            2,
            "the test keeps the managed stream peers open after adapter drop",
        );

        let read = tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf))
            .await
            .expect("bridge task drop should close the peer fd")
            .expect("read after adapter drop");

        assert_eq!(read, 0);
        drop((server_sink, server_stream, client_sink, client_stream));
    }
}
