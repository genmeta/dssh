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
use crate::conversation::Conversation;
use crate::forward::{
    DirectStreamlocal, DirectTcpip, ForwardedStreamlocal, ForwardedTcpip,
    StreamlocalForwardGlobalRequest, StreamlocalForwardRequest, TcpipForwardGlobalRequest,
    TcpipForwardReply, TcpipForwardRequest, relay,
};
use h3x::varint::VarInt;

use super::spec::{Endpoint, LocalForward, RemoteForward};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectOriginator {
    host: String,
    port: u16,
}

impl DirectOriginator {
    fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        Self {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    fn placeholder() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 65535,
        }
    }
}

fn remote_forward_bind_key(bind: &Endpoint) -> Option<(String, u16)> {
    match bind {
        Endpoint::Tcp { host, port } => Some((
            crate::forward::canonicalize_remote_bind_host(host).into_owned(),
            *port,
        )),
        Endpoint::Unix { .. } => None,
    }
}

fn forwarded_tcpip_bind_key(host: &str, port: u16) -> (String, u16) {
    (
        crate::forward::canonicalize_remote_bind_host(host).into_owned(),
        port,
    )
}

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
    pub async fn run<S>(
        &self,
        conversation: Arc<Conversation<S>>,
    ) -> Result<Infallible, BindLocalForwardError>
    where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
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

    async fn accept_loop_tcp<S>(
        &self,
        listener: tokio::net::TcpListener,
        conversation: Arc<Conversation<S>>,
    ) -> Result<Infallible, BindLocalForwardError>
    where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
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
            let originator = DirectOriginator::from_socket_addr(peer);
            let (r, w) = stream.into_split();
            tasks.spawn(
                open_channel_and_relay(conv, connect, originator, Box::pin(r), Box::pin(w))
                    .instrument(tracing::info_span!("conn", %peer)),
            );
        }
    }

    #[cfg(unix)]
    async fn accept_loop_unix<S>(
        &self,
        listener: tokio::net::UnixListener,
        conversation: Arc<Conversation<S>>,
    ) -> Result<Infallible, BindLocalForwardError>
    where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
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
                open_channel_and_relay(
                    conv,
                    connect,
                    DirectOriginator::placeholder(),
                    Box::pin(r),
                    Box::pin(w),
                )
                .in_current_span(),
            );
        }
    }
}

/// Open an SSH channel to the connect endpoint and relay data bidirectionally.
async fn open_channel_and_relay<S>(
    conversation: Arc<Conversation<S>>,
    connect: Endpoint,
    originator: DirectOriginator,
    local_reader: Pin<Box<dyn AsyncRead + Send>>,
    local_writer: Pin<Box<dyn AsyncWrite + Send>>,
) where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
{
    let channel_result = match &connect {
        Endpoint::Tcp { host, port } => {
            conversation
                .open_channel(
                    &DirectTcpip {
                        dest_host: SshString::from(host.clone()),
                        dest_port: VarInt::from(*port as u32),
                        originator_host: SshString::from(originator.host.clone()),
                        originator_port: VarInt::from(originator.port as u32),
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
    pub async fn request<S>(
        &self,
        conversation: &Conversation<S>,
    ) -> Result<RemoteForwardEstablished, RequestRemoteForwardError>
    where
        S: h3x::webtransport::Session,
    {
        use request_remote_forward_error::*;

        match &self.bind {
            Endpoint::Tcp { host, port } => {
                let canonical_host =
                    crate::forward::canonicalize_remote_bind_host(host).into_owned();
                let request = TcpipForwardGlobalRequest {
                    payload: TcpipForwardRequest {
                        bind_address: SshString::from(canonical_host.clone()),
                        bind_port: VarInt::from(*port as u32),
                    },
                };
                let reply: TcpipForwardReply = conversation
                    .send_global_request(&request)
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
                        host: canonical_host,
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
                    .send_global_request(&request)
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
pub async fn accept_forwarded_channels<S>(
    conversation: Arc<Conversation<S>>,
    mappings: Vec<RemoteForwardEstablished>,
) where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
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
                let incoming_key = forwarded_tcpip_bind_key(&server_addr, server_port);

                let mapping = mappings.iter().find(|m| match &m.bind {
                    Endpoint::Tcp { .. } => {
                        remote_forward_bind_key(&m.bind) == Some(incoming_key.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{SshBool, SshString};
    use crate::test_support::{MockWebTransportSession as TestSession, stream_pair as make_half};
    use h3x::{
        codec::{DecodeExt, EncodeExt},
        stream_id::StreamId,
        varint::VarInt,
    };
    use tokio::io::{AsyncWriteExt, empty, sink};

    fn make_test_session() -> TestSession {
        TestSession::new(StreamId(VarInt::from_u32(40)))
    }

    fn make_conversation(session: TestSession) -> Arc<Conversation<TestSession>> {
        let stream_id = VarInt::from_u32(40);
        let (local_reader, _remote_writer) = make_half(stream_id);
        let (_remote_reader, local_writer) = make_half(stream_id);
        Arc::new(Conversation::from_control_streams(
            session,
            "test",
            local_reader,
            local_writer,
        ))
    }

    #[tokio::test]
    async fn direct_tcpip_uses_real_tcp_originator() {
        let session = make_test_session();
        let conv = make_conversation(session.clone());

        let stream_id = VarInt::from_u32(44);
        let (mut remote_rd, local_wr) = make_half(stream_id);
        let (local_rd, mut remote_wr) = make_half(stream_id);
        session.provide_open_stream(local_rd, local_wr);

        let handle = tokio::spawn(open_channel_and_relay(
            Arc::clone(&conv),
            Endpoint::Tcp {
                host: "example.com".into(),
                port: 443,
            },
            DirectOriginator::from_socket_addr("127.0.0.1:2222".parse().unwrap()),
            Box::pin(empty()),
            Box::pin(sink()),
        ));

        let _stream_kind: VarInt = remote_rd.decode_one().await.unwrap();
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _dest_host: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _dest_port: VarInt = remote_rd.decode_one().await.unwrap();
        let originator_host: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let originator_port: VarInt = remote_rd.decode_one().await.unwrap();

        assert_eq!(&*originator_host, "127.0.0.1");
        assert_eq!(originator_port, VarInt::from_u32(2222));

        remote_wr.encode_one(VarInt::from_u32(91)).await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap();
        drop(remote_wr);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn direct_tcpip_uses_placeholder_originator_for_unix_forwarders() {
        let session = make_test_session();
        let conv = make_conversation(session.clone());

        let stream_id = VarInt::from_u32(46);
        let (mut remote_rd, local_wr) = make_half(stream_id);
        let (local_rd, mut remote_wr) = make_half(stream_id);
        session.provide_open_stream(local_rd, local_wr);

        let handle = tokio::spawn(open_channel_and_relay(
            Arc::clone(&conv),
            Endpoint::Tcp {
                host: "example.com".into(),
                port: 443,
            },
            DirectOriginator::placeholder(),
            Box::pin(empty()),
            Box::pin(sink()),
        ));

        let _stream_kind: VarInt = remote_rd.decode_one().await.unwrap();
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _dest_host: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _dest_port: VarInt = remote_rd.decode_one().await.unwrap();
        let originator_host: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let originator_port: VarInt = remote_rd.decode_one().await.unwrap();

        assert_eq!(&*originator_host, "127.0.0.1");
        assert_eq!(originator_port, VarInt::from_u32(65535));

        remote_wr.encode_one(VarInt::from_u32(91)).await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap();
        drop(remote_wr);
        handle.await.unwrap();
    }

    #[test]
    fn remote_forward_bind_key_normalizes_wildcard_and_preserves_explicit_hosts() {
        assert_eq!(
            remote_forward_bind_key(&Endpoint::Tcp {
                host: "*".into(),
                port: 9000,
            }),
            Some(("".to_owned(), 9000))
        );
        assert_eq!(
            remote_forward_bind_key(&Endpoint::Tcp {
                host: "localhost".into(),
                port: 9000,
            }),
            Some(("localhost".to_owned(), 9000))
        );
        assert_eq!(
            remote_forward_bind_key(&Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 9000,
            }),
            Some(("127.0.0.1".to_owned(), 9000))
        );
    }

    #[test]
    fn forwarded_tcpip_bind_key_uses_canonical_semantics() {
        assert_eq!(forwarded_tcpip_bind_key("*", 9000), ("".to_owned(), 9000));
        assert_eq!(forwarded_tcpip_bind_key("", 9000), ("".to_owned(), 9000));
        assert_eq!(
            forwarded_tcpip_bind_key("localhost", 9000),
            ("localhost".to_owned(), 9000)
        );
        assert_eq!(
            forwarded_tcpip_bind_key("::", 9000),
            ("::".to_owned(), 9000)
        );
    }

    #[tokio::test]
    async fn remote_forward_request_sends_canonical_bind_host() {
        let session = make_test_session();

        let stream_id = VarInt::from_u32(52);
        let (local_reader, mut remote_writer) = make_half(stream_id);
        let (mut remote_reader, local_writer) = make_half(stream_id);
        let conv = Conversation::from_control_streams(session, "test", local_reader, local_writer);

        let handle = tokio::spawn(async move {
            let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
            assert_eq!(msg_type, VarInt::from_u32(80));
            let request_type: SshString = remote_reader.decode_one().await.unwrap();
            assert_eq!(&*request_type, "tcpip-forward");
            let want_reply: SshBool = remote_reader.decode_one().await.unwrap();
            assert!(want_reply.0);
            let bind_host: SshString = remote_reader.decode_one().await.unwrap();
            let bind_port: VarInt = remote_reader.decode_one().await.unwrap();
            assert_eq!(&*bind_host, "");
            assert_eq!(bind_port, VarInt::from_u32(9000));
            remote_writer
                .encode_one(VarInt::from_u32(81))
                .await
                .unwrap();
            remote_writer
                .encode_one(VarInt::from_u32(9000))
                .await
                .unwrap();
            remote_writer.flush().await.unwrap();
        });

        let established = RemoteForward {
            bind: Endpoint::Tcp {
                host: "*".into(),
                port: 9000,
            },
            connect: Some(Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 22,
            }),
        }
        .request(&conv)
        .await
        .unwrap();

        assert_eq!(
            established.bind,
            Endpoint::Tcp {
                host: "".into(),
                port: 9000,
            }
        );

        handle.await.unwrap();
    }
}
