use std::{path::PathBuf, sync::Arc};

use crate::entry_guard::EntryGuard;
use bytes::Bytes;
use dashmap::DashMap;
use either::Either;
use futures::StreamExt;
use snafu::{ResultExt, Snafu};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    messages::{BindAddress, Request},
    mux::{self, Mux, Recver, Sender, Token},
};

/// Forward data from local to remote
pub struct LocalForwarder {
    mux: Arc<Mux>,
    open: Request,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum LocalForwardError {
    #[snafu(display("Failed to open channel for forwarding"))]
    Request { source: mux::ChannelError },
    #[snafu(display("Failed to copy data between streams"))]
    Copy { source: io::Error },
}

#[derive(Debug, Snafu)]
#[snafu(display("Failed to connect to local `{bind_addr}`"))]
#[snafu(visibility(pub))]
pub struct ConnectLocalError {
    bind_addr: BindAddress,
    source: io::Error,
}

impl LocalForwarder {
    pub fn new(mux: Arc<Mux>, open: Request) -> Self {
        Self { mux, open }
    }

    pub fn open_channel(
        &self,
    ) -> impl Future<Output = Result<(Token, Recver, Sender), mux::ChannelError>> + Send + use<>
    {
        let (mux, open) = (self.mux.clone(), self.open.clone());
        async move { mux.request(open).await }
    }

    pub fn forward<R, W>(
        &self,
        reader: R,
        writer: W,
    ) -> impl Future<Output = Result<(), LocalForwardError>> + Send + use<R, W>
    where
        R: AsyncRead + Send + Unpin,
        W: AsyncWrite + Send + Unpin,
    {
        let open_channel = self.open_channel();

        async move {
            let (_token, recver, sender) = open_channel.await.context(RequestSnafu)?;
            let mut stream = io::join(reader, writer);
            let mut forward_stream = io::join(recver.streaming(), sender.streaming());
            // 错误：1. 连接断开（无需处理） 2. 对方Error（无需处理）
            let copy_result = io::copy_bidirectional(&mut stream, &mut forward_stream).await;
            _ = stream.shutdown().await;
            _ = forward_stream.shutdown().await;
            copy_result.map(|_| ()).context(CopySnafu)
        }
    }
}

pub async fn accept_tcp_forward(
    mut sender: Sender,
    recver: Recver,
    host: &str,
    port: u16,
) -> Result<impl Future<Output = Result<(), LocalForwardError>> + use<>, ConnectLocalError> {
    let mut tcp_stream = match TcpStream::connect((host, port)).await {
        Ok(tcp_stream) => tcp_stream,
        Err(connect_error) => {
            _ = sender
                .cancel(format!(
                    "Peer failed to connect to {host}:{port}: {connect_error:?}"
                ))
                .await;

            return Err(connect_error).context(ConnectLocalSnafu {
                bind_addr: BindAddress::Host {
                    host: host.to_string(),
                    port,
                },
            });
        }
    };
    Ok(async move {
        let mut forward_stream = io::join(recver.streaming(), sender.streaming());
        io::copy_bidirectional(&mut forward_stream, &mut tcp_stream)
            .await
            .context(CopySnafu)?;
        _ = tcp_stream.shutdown().await;
        _ = forward_stream.shutdown().await;

        Ok(())
    })
}

#[cfg(unix)]
pub async fn accept_unix_forward(
    mut sender: Sender,
    recver: Recver,
    endpoint: PathBuf,
) -> Result<impl Future<Output = Result<(), LocalForwardError>>, ConnectLocalError> {
    let mut unix_stream = match UnixStream::connect(endpoint.clone()).await {
        Ok(unix_stream) => unix_stream,
        Err(connect_error) => {
            _ = sender
                .cancel(format!(
                    "Peer failed to connect to {endpoint:?}: {connect_error:?}"
                ))
                .await;

            return Err(connect_error).context(ConnectLocalSnafu {
                bind_addr: BindAddress::Unix { path: endpoint },
            });
        }
    };

    Ok(async move {
        let mut forward_stream = io::join(recver.streaming(), sender.streaming());
        io::copy_bidirectional(&mut forward_stream, &mut unix_stream)
            .await
            .context(CopySnafu)?;
        _ = unix_stream.shutdown().await;
        _ = forward_stream.shutdown().await;

        Ok(())
    })
}

#[cfg(not(unix))]
async fn reject_unix_forward(
    mut sender: Sender,
    _recver: Recver,
    _endpoint: PathBuf,
) -> Result<impl Future<Output = Result<(), LocalForwardError>>, ConnectLocalError> {
    _ = sender
        .cancel(io::Error::new(
            io::ErrorKind::Unsupported,
            "UNIX domain sockets are not supported for this platform.",
        ))
        .await;
    Ok(async { Ok(()) })
}

pub async fn accept_forward(
    sender: Sender,
    recver: Recver,
    local: BindAddress,
) -> Result<impl Future<Output = Result<(), LocalForwardError>>, ConnectLocalError> {
    let future = match local {
        BindAddress::Host { host, port } => {
            Either::Left(accept_tcp_forward(sender, recver, &host, port).await?)
        }
        #[cfg(unix)]
        BindAddress::Unix { path } => {
            Either::Right(accept_unix_forward(sender, recver, path).await?)
        }
        #[cfg(not(unix))]
        BindAddress::Unix { path } => {
            Either::Right(reject_unix_forward(sender, recver, path).await?)
        }
    };

    Ok(future)
}

/// Forward data from remote to local
pub struct RemoteForwardAcceptor {
    mux: Arc<Mux>,
    forwards: Arc<DashMap<Token, Option<BindAddress>>>,
}

impl RemoteForwardAcceptor {
    pub fn new(mux: Arc<Mux>) -> Self {
        Self {
            mux,
            forwards: Arc::new(DashMap::new()),
        }
    }

    pub async fn accept(
        &self,
        token: Token,
        local: Option<BindAddress>,
        recver: Recver,
        mut sender: Sender,
    ) -> Result<
        Option<impl Future<Output = Result<(), LocalForwardError>> + Send + use<>>,
        ConnectLocalError,
    > {
        let Some(bind_addr) = self.forwards.get(&token) else {
            _ = sender
                .cancel("Not allowed to forward to this endpoint")
                .await;
            return Ok(None);
        };
        let Some(local) = local.or_else(|| bind_addr.value().clone()) else {
            _ = sender
                .cancel("No target address provided(Internal error, this is a bug)")
                .await;
            return Ok(None);
        };

        accept_forward(sender, recver, local).await.map(Some)
    }

    /// Initial a channel, allow peer to open local forward
    pub async fn initial_forward(
        &self,
        local: Option<BindAddress>,
        remote: BindAddress,
    ) -> Result<impl Future<Output = io::Result<()>> + Send + use<>, mux::ChannelError> {
        let (token, recver, _sender) = self
            .mux
            .request(Request::Forward {
                listen: remote,
                socks: local.is_none(),
            })
            .await?;

        self.forwards.insert(token, local);

        let entry_guard = EntryGuard::new(self.forwards.clone(), token);

        Ok(async move {
            let _entry_guard = entry_guard;
            let mut recver = recver.framed::<Bytes>();
            while let Some(next) = recver.next().await {
                next?;
            }
            Ok(())
        })
    }
}
