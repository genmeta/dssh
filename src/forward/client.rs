//! Client-side forwarding runtime.
//!
//! Methods on [`LocalForward`] and [`RemoteForward`] to execute forwarding
//! rules on a [`Conversation`].

use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use snafu::{Report, ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Instrument;

use crate::codec::SshString;
use crate::constants::DEFAULT_MAX_MESSAGE_SIZE;
use crate::conversation::{Conversation, ManageSessionStream};
use crate::forward::{
    DirectStreamlocal, DirectTcpip, ForwardedStreamlocal, ForwardedTcpip,
    StreamlocalForwardGlobalRequest, StreamlocalForwardRequest, TcpipForwardGlobalRequest,
    TcpipForwardReply, TcpipForwardRequest, relay,
};
use h3x::varint::VarInt;

use super::spec::{Endpoint, LocalForward, RemoteForward};

// ============================================================================
// Error types
// ============================================================================

/// Error returned when [`LocalForward::run`] fails to bind the local listener.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum BindLocalForwardError {
    #[snafu(display("failed to bind TCP listener"))]
    TcpBind { source: io::Error },
    #[cfg(unix)]
    #[snafu(display("failed to bind Unix listener"))]
    UnixBind { source: io::Error },
    #[cfg(not(unix))]
    #[snafu(display("unix socket forwarding is not supported on this platform"))]
    UnixUnsupported,
}

/// Error from [`RemoteForward::request`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RequestRemoteForwardError {
    #[snafu(display("tcpip-forward request was rejected by remote"))]
    TcpForwardRejected,
    #[snafu(display("streamlocal-forward request was rejected by remote"))]
    StreamlocalForwardRejected,
    #[snafu(display("failed to send tcpip-forward request"))]
    TcpForwardRequest { source: RequestError },
    #[snafu(display("failed to send streamlocal-forward request"))]
    StreamlocalForwardRequest { source: RequestError },
}

/// Opaque wrapper for conversation request errors (avoids leaking generics).
#[derive(Debug, Snafu)]
#[snafu(display("{message}"))]
pub struct RequestError {
    message: String,
}

/// Result from a successful [`RemoteForward::request`].
pub struct RemoteForwardEstablished {
    /// The actual bind endpoint (port may differ if server allocated a dynamic port).
    pub bind: Endpoint,
    /// The local connect endpoint (cloned from the forward spec).
    pub connect: Option<Endpoint>,
}

// ============================================================================
// LocalForward runtime
// ============================================================================

impl LocalForward {
    /// Run this local forward: bind a local listener and, for each accepted
    /// connection, open an SSH channel to the remote connect endpoint and relay
    /// data bidirectionally.
    ///
    /// This function runs an infinite accept loop and only returns if the
    /// initial bind fails.
    pub async fn run<M>(
        &self,
        conversation: Arc<Conversation<M>>,
    ) -> Result<Infallible, BindLocalForwardError>
    where
        M: ManageSessionStream + 'static,
        M::StreamReader: 'static,
        M::StreamWriter: 'static,
    {
        match &self.bind {
            Endpoint::Tcp { host, port } => {
                let bind_addr = match host.as_str() {
                    "" | "*" => "0.0.0.0",
                    other => other,
                };
                let listener = tokio::net::TcpListener::bind((bind_addr, *port))
                    .await
                    .context(bind_local_forward_error::TcpBindSnafu)?;
                tracing::info!(
                    bind = %listener.local_addr().unwrap_or_else(|_| "?".parse().unwrap()),
                    "local forward listening"
                );
                self.accept_loop_tcp(listener, conversation).await
            }
            #[cfg(unix)]
            Endpoint::Unix { path } => {
                let listener = tokio::net::UnixListener::bind(path)
                    .context(bind_local_forward_error::UnixBindSnafu)?;
                tracing::info!(bind = %self.bind, "local forward listening");
                self.accept_loop_unix(listener, conversation).await
            }
            #[cfg(not(unix))]
            Endpoint::Unix { .. } => Err(BindLocalForwardError::UnixUnsupported),
        }
    }

    async fn accept_loop_tcp<M>(
        &self,
        listener: tokio::net::TcpListener,
        conversation: Arc<Conversation<M>>,
    ) -> Result<Infallible, BindLocalForwardError>
    where
        M: ManageSessionStream + 'static,
        M::StreamReader: 'static,
        M::StreamWriter: 'static,
    {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %Report::from_error(&e), "accept failed");
                    continue;
                }
            };
            let conv = conversation.clone();
            let connect = self.connect.clone();
            let (r, w) = stream.into_split();
            tasks.spawn(
                open_channel_and_relay(conv, connect, Box::pin(r), Box::pin(w))
                    .instrument(tracing::info_span!("conn", %peer)),
            );
        }
    }

    #[cfg(unix)]
    async fn accept_loop_unix<M>(
        &self,
        listener: tokio::net::UnixListener,
        conversation: Arc<Conversation<M>>,
    ) -> Result<Infallible, BindLocalForwardError>
    where
        M: ManageSessionStream + 'static,
        M::StreamReader: 'static,
        M::StreamWriter: 'static,
    {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %Report::from_error(&e), "accept failed");
                    continue;
                }
            };
            let conv = conversation.clone();
            let connect = self.connect.clone();
            let (r, w) = stream.into_split();
            tasks.spawn(
                open_channel_and_relay(conv, connect, Box::pin(r), Box::pin(w)).in_current_span(),
            );
        }
    }
}

/// Open an SSH channel to the connect endpoint and relay data bidirectionally.
async fn open_channel_and_relay<M>(
    conversation: Arc<Conversation<M>>,
    connect: Endpoint,
    local_reader: Pin<Box<dyn AsyncRead + Send>>,
    local_writer: Pin<Box<dyn AsyncWrite + Send>>,
) where
    M: ManageSessionStream + 'static,
    M::StreamReader: 'static,
    M::StreamWriter: 'static,
{
    let channel_result = match &connect {
        Endpoint::Tcp { host, port } => {
            conversation
                .open_channel(
                    &DirectTcpip {
                        dest_host: SshString::from(host.clone()),
                        dest_port: VarInt::from(*port as u32),
                        originator_host: SshString::from_static(""),
                        originator_port: VarInt::from(0u32),
                    },
                    DEFAULT_MAX_MESSAGE_SIZE,
                )
                .await
        }
        Endpoint::Unix { path } => {
            conversation
                .open_channel(
                    &DirectStreamlocal {
                        socket_path: SshString::from(path.clone()),
                    },
                    DEFAULT_MAX_MESSAGE_SIZE,
                )
                .await
        }
    };

    let (ch_reader, ch_writer) = match channel_result {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                error = %snafu::Report::from_error(&e),
                dest = %connect,
                "channel open failed"
            );
            return;
        }
    };

    let ch2s = tokio::spawn(relay(ch_reader, local_writer).in_current_span());
    let s2ch = tokio::spawn(relay(local_reader, ch_writer).in_current_span());
    let _ = tokio::join!(ch2s, s2ch);
}

// ============================================================================
// RemoteForward runtime
// ============================================================================

impl RemoteForward {
    /// Send a global request to the server to start listening on the remote
    /// bind endpoint. Returns the established binding info (including any
    /// server-allocated port).
    pub async fn request<M: ManageSessionStream>(
        &self,
        conversation: &Conversation<M>,
    ) -> Result<RemoteForwardEstablished, RequestRemoteForwardError> {
        use request_remote_forward_error::*;

        match &self.bind {
            Endpoint::Tcp { host, port } => {
                let request = TcpipForwardGlobalRequest {
                    payload: TcpipForwardRequest {
                        bind_address: SshString::from(host.clone()),
                        bind_port: VarInt::from(*port as u32),
                    },
                };
                let reply: TcpipForwardReply = conversation
                    .request(&request)
                    .await
                    .map_err(|e| RequestError {
                        message: e.to_string(),
                    })
                    .context(TcpForwardRequestSnafu)?;

                let allocated_port = reply.allocated_port.into_inner() as u16;
                tracing::info!(
                    bind = %Endpoint::Tcp { host: host.clone(), port: allocated_port },
                    connect = ?self.connect.as_ref().map(|c| c.to_string()),
                    "remote forward established"
                );

                Ok(RemoteForwardEstablished {
                    bind: Endpoint::Tcp {
                        host: host.clone(),
                        port: allocated_port,
                    },
                    connect: self.connect.clone(),
                })
            }
            Endpoint::Unix { path } => {
                let request = StreamlocalForwardGlobalRequest {
                    payload: StreamlocalForwardRequest {
                        socket_path: SshString::from(path.clone()),
                    },
                };
                conversation
                    .request(&request)
                    .await
                    .map_err(|e| RequestError {
                        message: e.to_string(),
                    })
                    .context(StreamlocalForwardRequestSnafu)?;

                tracing::info!(
                    bind = %self.bind,
                    connect = ?self.connect.as_ref().map(|c| c.to_string()),
                    "remote forward established (unix socket)"
                );

                Ok(RemoteForwardEstablished {
                    bind: Endpoint::Unix { path: path.clone() },
                    connect: self.connect.clone(),
                })
            }
        }
    }
}

// ============================================================================
// Channel acceptor for remote forwards
// ============================================================================

/// Connect to a local endpoint (TCP or Unix socket).
pub async fn connect_locally(
    endpoint: &Endpoint,
) -> io::Result<(
    Pin<Box<dyn AsyncRead + Send>>,
    Pin<Box<dyn AsyncWrite + Send>>,
)> {
    match endpoint {
        Endpoint::Tcp { host, port } => {
            let stream = tokio::net::TcpStream::connect((host.as_str(), *port)).await?;
            let (r, w) = stream.into_split();
            Ok((Box::pin(r), Box::pin(w)))
        }
        #[cfg(unix)]
        Endpoint::Unix { path } => {
            let stream = tokio::net::UnixStream::connect(path).await?;
            let (r, w) = stream.into_split();
            Ok((Box::pin(r), Box::pin(w)))
        }
        #[cfg(not(unix))]
        Endpoint::Unix { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unix socket is not supported on this platform",
        )),
    }
}

/// Accept incoming channels from the server (`forwarded-tcpip` and
/// `forwarded-streamlocal@openssh.com`) and relay them to local endpoints
/// based on the provided mappings.
///
/// Runs until the conversation's channel accept stream ends.
pub async fn accept_forwarded_channels<M>(
    conversation: Arc<Conversation<M>>,
    mappings: Vec<RemoteForwardEstablished>,
) where
    M: ManageSessionStream + 'static,
    M::StreamReader: 'static,
    M::StreamWriter: 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let incoming = match conversation.accept_channel().await {
            Ok(ch) => ch,
            Err(e) => {
                tracing::debug!(
                    error = %snafu::Report::from_error(&e),
                    "accept_channel ended"
                );
                break;
            }
        };

        let channel_type = incoming.channel_type().to_string();

        match channel_type.as_str() {
            "forwarded-tcpip" => {
                let (payload, pending): (ForwardedTcpip, _) = match incoming.decode_payload().await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            error = %snafu::Report::from_error(&e),
                            "decode forwarded-tcpip failed"
                        );
                        continue;
                    }
                };

                let server_port = payload.connected_port.into_inner() as u16;
                let server_addr = payload.connected_address.to_string();

                let mapping = mappings.iter().find(|m| match &m.bind {
                    Endpoint::Tcp { host, port } => {
                        *port == server_port
                            && (host.is_empty()
                                || host == "0.0.0.0"
                                || host == "*"
                                || *host == server_addr)
                    }
                    _ => false,
                });

                let Some(RemoteForwardEstablished {
                    connect: Some(connect),
                    ..
                }) = mapping
                else {
                    tracing::warn!(
                        %server_addr, server_port,
                        "no matching remote forward target, rejecting"
                    );
                    let _ = pending
                        .reject(
                            VarInt::from(2u32),
                            SshString::from_static("no matching forward"),
                        )
                        .await;
                    continue;
                };

                let connect = connect.clone();
                tasks.spawn(handle_forwarded_channel(pending, connect).instrument(
                    tracing::info_span!(
                        "remote_forward_conn",
                        %server_addr,
                        server_port,
                    ),
                ));
            }
            "forwarded-streamlocal@openssh.com" => {
                let (payload, pending): (ForwardedStreamlocal, _) =
                    match incoming.decode_payload().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(
                                error = %snafu::Report::from_error(&e),
                                "decode forwarded-streamlocal failed"
                            );
                            continue;
                        }
                    };

                let socket_path = payload.socket_path.to_string();

                let mapping = mappings.iter().find(|m| match &m.bind {
                    Endpoint::Unix { path } => *path == socket_path,
                    _ => false,
                });

                let Some(RemoteForwardEstablished {
                    connect: Some(connect),
                    ..
                }) = mapping
                else {
                    tracing::warn!(
                        %socket_path,
                        "no matching remote forward target, rejecting"
                    );
                    let _ = pending
                        .reject(
                            VarInt::from(2u32),
                            SshString::from_static("no matching forward"),
                        )
                        .await;
                    continue;
                };

                let connect = connect.clone();
                tasks.spawn(handle_forwarded_channel(pending, connect).instrument(
                    tracing::info_span!(
                        "remote_forward_conn",
                        %socket_path,
                    ),
                ));
            }
            _ => {
                tracing::warn!(channel_type, "rejecting unknown incoming channel");
                if let Ok((_, pending)) = incoming.decode_payload::<ForwardedTcpip, _>().await {
                    let _ = pending
                        .reject(
                            VarInt::from(1u32),
                            SshString::from_static("unsupported channel type"),
                        )
                        .await;
                }
            }
        }
    }
}

/// Handle a single forwarded channel: connect locally and relay data.
async fn handle_forwarded_channel<R, W>(
    pending: crate::conversation::channel::PendingChannel<R, W>,
    connect: Endpoint,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (local_reader, local_writer) = match connect_locally(&connect).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                dest = %connect,
                error = %e,
                "failed to connect to local target"
            );
            let _ = pending
                .reject(VarInt::from(2u32), SshString::from_static("connect failed"))
                .await;
            return;
        }
    };

    let (ch_reader, ch_writer) = match pending.accept(DEFAULT_MAX_MESSAGE_SIZE).await {
        Ok(ch) => ch.into_inner(),
        Err(e) => {
            tracing::warn!(
                error = %snafu::Report::from_error(&e),
                "channel accept failed"
            );
            return;
        }
    };

    let ch2s = tokio::spawn(relay(ch_reader, local_writer).in_current_span());
    let s2ch = tokio::spawn(relay(local_reader, ch_writer).in_current_span());
    let _ = tokio::join!(ch2s, s2ch);
}
