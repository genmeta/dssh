//! Reverse forwarding: bind listeners that open DShell channels back to the
//! client for each accepted connection.
//!
//! Use [`DecodedGlobalRequest::accept_tcp_forward`] and
//! [`DecodedGlobalRequest::accept_unix_forward`] to accept a forwarding
//! request (bind listener + respond to remote). The returned listener
//! struct has a [`run`](TcpForwardListener::run) method that drives the
//! accept loop.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{
    constants::DEFAULT_MAX_MESSAGE_SIZE,
    conversation::global::{DecodedGlobalRequest, RespondSuccessError},
    conversation::{ChannelOpen, Conversation},
    forward::{
        ForwardError, ForwardedStreamlocal, ForwardedTcpip, StreamlocalForwardRequest,
        TcpipForwardReply, TcpipForwardRequest, relay,
    },
};
use h3x::codec::EncodeInto;
use h3x::varint::VarInt;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum AcceptTcpForwardError {
    #[snafu(display("bind port overflows u16"))]
    PortOverflow,

    #[snafu(display("failed to resolve TCP bind address {host}"))]
    ResolveBindAddress {
        host: String,
        source: std::io::Error,
    },

    #[snafu(display("failed to bind TCP listener"))]
    TcpBind { source: std::io::Error },

    #[snafu(display("failed to get local address of TCP listener"))]
    LocalAddr { source: std::io::Error },

    #[snafu(display("failed to send success response"))]
    Respond {
        source: RespondSuccessError<ForwardError>,
    },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum AcceptUnixForwardError {
    #[snafu(display("failed to bind Unix listener"))]
    UnixBind { source: std::io::Error },

    #[snafu(display("failed to send success response"))]
    Respond {
        source: RespondSuccessError<std::convert::Infallible>,
    },
}

fn bind_candidates(host: &str) -> Vec<std::net::SocketAddr> {
    match host {
        "localhost" => vec![
            std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
            std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
        ],
        "" => vec![
            std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        ],
        "0.0.0.0" => vec![std::net::SocketAddr::from((
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))],
        "::" => vec![std::net::SocketAddr::from((
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
        ))],
        "127.0.0.1" => vec![std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        ))],
        "::1" => vec![std::net::SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            0,
        ))],
        _ => vec![],
    }
}

async fn resolve_bind_candidates(
    host: &str,
) -> Result<Vec<std::net::SocketAddr>, AcceptTcpForwardError> {
    let semantic = bind_candidates(host);
    if !semantic.is_empty() {
        return Ok(semantic);
    }

    let mut addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, 0))
        .await
        .context(accept_tcp_forward_error::ResolveBindAddressSnafu {
            host: host.to_owned(),
        })?
        .collect();
    addrs.sort_by_key(|addr| match addr {
        std::net::SocketAddr::V6(_) => 0,
        std::net::SocketAddr::V4(_) => 1,
    });
    addrs.dedup();
    Ok(addrs)
}

fn bind_tcp_socket(addr: std::net::SocketAddr) -> std::io::Result<TcpListener> {
    use std::os::fd::AsRawFd;
    use tokio::net::TcpSocket;

    match addr {
        std::net::SocketAddr::V4(addr) => {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true)?;
            socket.bind(std::net::SocketAddr::V4(addr))?;
            socket.listen(1024)
        }
        std::net::SocketAddr::V6(addr) => {
            let socket = TcpSocket::new_v6()?;
            socket.set_reuseaddr(true)?;
            let yes: libc::c_int = 1;
            // SAFETY: setsockopt writes a small integer option to a valid socket
            // file descriptor before bind.
            let rc = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &yes as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&yes) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            socket.bind(std::net::SocketAddr::V6(addr))?;
            socket.listen(1024)
        }
    }
}

// ---------------------------------------------------------------------------
// TCP forward listener
// ---------------------------------------------------------------------------

/// A bound TCP listener ready to accept reverse-forwarded connections.
///
/// Obtained from [`DecodedGlobalRequest::accept_tcp_forward`].
pub struct TcpForwardListener {
    advertised_host: String,
    bound_port: u16,
    listeners: Vec<TcpListener>,
}

impl TcpForwardListener {
    /// Bind a TCP listener at the given address.
    pub async fn bind(addr: impl tokio::net::ToSocketAddrs) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        Ok(Self {
            advertised_host: bound_addr.ip().to_string(),
            bound_port: bound_addr.port(),
            listeners: vec![listener],
        })
    }

    /// The address the listener is bound to.
    pub fn bound_addr(&self) -> SocketAddr {
        self.listeners[0]
            .local_addr()
            .expect("single-listener bound address should be available")
    }

    pub fn bound_port(&self) -> u16 {
        self.bound_port
    }

    pub fn advertised_host(&self) -> &str {
        &self.advertised_host
    }

    /// Run the accept loop, opening a `forwarded-tcpip` channel for each
    /// accepted connection and relaying data bidirectionally.
    ///
    /// Runs until the listener encounters an accept error. Cancel the
    /// enclosing task to stop the listener.
    pub async fn run<S>(
        self,
        conversation: Arc<Conversation<S>>,
        relay_tasks: TaskTracker,
        relay_cancel: CancellationToken,
    ) where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
    {
        let connected_port = self.bound_port;
        let connected_addr = self.advertised_host.clone();
        let mut listeners = JoinSet::new();
        for listener in self.listeners {
            let conversation = Arc::clone(&conversation);
            let connected_addr = connected_addr.clone();
            let relay_tasks = relay_tasks.clone();
            let relay_cancel = relay_cancel.clone();
            listeners.spawn(
                async move {
                    run_tcp_accept_loop(
                        listener,
                        conversation,
                        connected_addr,
                        connected_port,
                        relay_tasks,
                        relay_cancel,
                    )
                    .await;
                }
                .in_current_span(),
            );
        }

        while let Some(result) = listeners.join_next().await {
            if let Err(error) = result {
                tracing::warn!(
                    error = %snafu::Report::from_error(&error),
                    "reverse-tcp listener task panicked"
                );
            }
        }
    }
}

async fn bind_tcp_forward_group(
    host: &str,
    bind_port: u16,
) -> Result<TcpForwardListener, AcceptTcpForwardError> {
    use accept_tcp_forward_error::*;

    let candidates = resolve_bind_candidates(host).await?;
    let mut listeners = Vec::new();
    let mut logical_port = None;

    for candidate in candidates {
        let requested = logical_port.unwrap_or(bind_port);
        let mut addr = candidate;
        addr.set_port(requested);
        match bind_tcp_socket(addr) {
            Ok(listener) => {
                if logical_port.is_none() {
                    let local_addr = listener.local_addr().context(LocalAddrSnafu)?;
                    logical_port = Some(local_addr.port());
                }
                listeners.push(listener);
            }
            Err(error) if logical_port.is_some() => {
                tracing::debug!(
                    error = %snafu::Report::from_error(&error),
                    %host,
                    requested,
                    "reverse-tcp secondary bind failed"
                );
            }
            Err(source) => return Err(AcceptTcpForwardError::TcpBind { source }),
        }
    }

    let Some(bound_port) = logical_port else {
        return Err(AcceptTcpForwardError::TcpBind {
            source: std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no listeners created",
            ),
        });
    };

    Ok(TcpForwardListener {
        advertised_host: host.to_owned(),
        bound_port,
        listeners,
    })
}

async fn run_tcp_accept_loop<S>(
    listener: TcpListener,
    conversation: Arc<Conversation<S>>,
    connected_addr: String,
    connected_port: u16,
    relay_tasks: TaskTracker,
    relay_cancel: CancellationToken,
) where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
{
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(
                    error = %snafu::Report::from_error(&e),
                    "reverse-tcp accept error, stopping listener"
                );
                break;
            }
        };

        let conversation = Arc::clone(&conversation);
        let connected_addr = connected_addr.clone();
        let relay_cancel = relay_cancel.clone();

        relay_tasks.spawn(
            async move {
                let channel_open = ForwardedTcpip {
                    connected_address: connected_addr.into(),
                    connected_port: (connected_port as u32).into(),
                    originator_address: peer_addr.ip().to_string().into(),
                    originator_port: (peer_addr.port() as u32).into(),
                };
                conversation
                    .open_channel_and_relay(channel_open, tcp_stream, relay_cancel)
                    .await;
            }
            .in_current_span(),
        );
    }
}

// ---------------------------------------------------------------------------
// Unix forward listener
// ---------------------------------------------------------------------------

/// A bound Unix socket listener ready to accept reverse-forwarded connections.
///
/// Obtained from [`DecodedGlobalRequest::accept_unix_forward`].
/// The socket file is automatically removed when this value is dropped.
pub struct UnixForwardListener {
    listener: UnixListener,
    guard: UnixSocketGuard,
}

impl UnixForwardListener {
    /// Bind a Unix socket at the given path.
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let path = path.as_ref();
        let listener = UnixListener::bind(path)?;
        Ok(Self {
            listener,
            guard: UnixSocketGuard(path.to_path_buf()),
        })
    }

    /// Run the accept loop, opening a `forwarded-streamlocal` channel for
    /// each accepted connection and relaying data bidirectionally.
    ///
    /// Runs until the listener encounters an accept error. Cancel the
    /// enclosing task to stop the listener. The socket file is removed
    /// when this future is dropped (including on cancellation).
    pub async fn run<S>(
        self,
        conversation: Arc<Conversation<S>>,
        relay_tasks: TaskTracker,
        relay_cancel: CancellationToken,
    ) where
        S: h3x::webtransport::Session + 'static,
        S::StreamReader: 'static,
        S::StreamWriter: 'static,
    {
        let _guard = self.guard;
        let socket_path = &_guard.0;

        loop {
            let (unix_stream, _) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(
                        error = %snafu::Report::from_error(&e),
                        "reverse-streamlocal accept error, stopping listener"
                    );
                    break;
                }
            };

            let conversation = Arc::clone(&conversation);
            let path = socket_path.display().to_string();
            let relay_cancel = relay_cancel.clone();

            relay_tasks.spawn(
                async move {
                    let channel_open = ForwardedStreamlocal {
                        socket_path: path.into(),
                    };
                    conversation
                        .open_channel_and_relay(channel_open, unix_stream, relay_cancel)
                        .await;
                }
                .in_current_span(),
            );
        }
    }
}

/// Guard that removes a Unix socket file on drop.
struct UnixSocketGuard(PathBuf);

impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------
// DecodedGlobalRequest methods for accepting forward requests
// ---------------------------------------------------------------------------

impl<R, W> DecodedGlobalRequest<TcpipForwardRequest, R, W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Accept a `tcpip-forward` request: bind a TCP listener, respond with
    /// the allocated port, and return the listener.
    ///
    /// On bind failure, responds with failure automatically.
    pub async fn accept_tcp_forward(self) -> Result<TcpForwardListener, AcceptTcpForwardError> {
        use accept_tcp_forward_error::*;

        let bind_address = self.payload().bind_address.to_string();
        let bind_host = crate::forward::canonicalize_remote_bind_host(&bind_address).into_owned();
        let bind_port = match u16::try_from(self.payload().bind_port.into_inner()) {
            Ok(port) => port,
            Err(_) => {
                let _ = self.respond_failure().await;
                return Err(AcceptTcpForwardError::PortOverflow);
            }
        };

        let listener = match bind_tcp_forward_group(&bind_host, bind_port).await {
            Ok(listener) => listener,
            Err(error) => {
                let _ = self.respond_failure().await;
                return Err(error);
            }
        };

        let reply = TcpipForwardReply {
            allocated_port: VarInt::from(listener.bound_port() as u32),
        };
        self.respond_success(reply).await.context(RespondSnafu)?;

        Ok(listener)
    }
}

impl<R, W> DecodedGlobalRequest<StreamlocalForwardRequest, R, W>
where
    W: AsyncWrite + Unpin + Send,
{
    /// Accept a `streamlocal-forward` request: bind a Unix socket, respond
    /// with success, and return the listener.
    ///
    /// On bind failure, responds with failure automatically.
    pub async fn accept_unix_forward(self) -> Result<UnixForwardListener, AcceptUnixForwardError> {
        use accept_unix_forward_error::*;

        let socket_path = self.payload().socket_path.to_string();

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(source) => {
                let _ = self.respond_failure().await;
                return Err(AcceptUnixForwardError::UnixBind { source });
            }
        };

        self.respond_success(crate::conversation::EmptyPayload)
            .await
            .context(RespondSnafu)?;

        Ok(UnixForwardListener {
            listener,
            guard: UnixSocketGuard(PathBuf::from(socket_path)),
        })
    }
}

// ---------------------------------------------------------------------------
// Conversation helper: open channel and relay
// ---------------------------------------------------------------------------

impl<S> Conversation<S>
where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
{
    /// Open a channel for reverse forwarding and relay `local_stream`
    /// through it bidirectionally.
    ///
    /// On failure to open the channel, logs a warning and returns silently.
    pub(crate) async fn open_channel_and_relay<C, T>(
        &self,
        channel_open: C,
        local_stream: T,
        relay_cancel: CancellationToken,
    ) where
        C: ChannelOpen,
        for<'w> C: EncodeInto<
                &'w mut h3x::codec::SinkWriter<S::StreamWriter>,
                Output = (),
                Error = ForwardError,
            >,
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = match self
            .open_channel(&channel_open, DEFAULT_MAX_MESSAGE_SIZE)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %snafu::Report::from_error(&e), "reverse channel open failed");
                return;
            }
        };

        let (local_reader, local_writer) = tokio::io::split(local_stream);
        let mut ch2s = tokio::spawn(relay(reader, local_writer).in_current_span());
        let mut s2ch = tokio::spawn(relay(local_reader, writer).in_current_span());
        let ch2s_abort = ch2s.abort_handle();
        let s2ch_abort = s2ch.abort_handle();
        enum RelayOutcome<A, B> {
            Joined((A, B)),
            Cancelled,
        }
        let relay_outcome = tokio::select! {
            _ = relay_cancel.cancelled() => {
                ch2s_abort.abort();
                s2ch_abort.abort();
                RelayOutcome::Cancelled
            }
            result = async {
                let r1 = (&mut ch2s).await;
                let r2 = (&mut s2ch).await;
                (r1, r2)
            } => RelayOutcome::Joined(result),
        };
        let (r1, r2) = match relay_outcome {
            RelayOutcome::Joined(result) => result,
            RelayOutcome::Cancelled => {
                let r1 = ch2s.await;
                let r2 = s2ch.await;
                (r1, r2)
            }
        };
        if let Err(e) = r1
            && !e.is_cancelled()
        {
            tracing::warn!(error = %snafu::Report::from_error(&e), "reverse relay task panicked");
        }
        if let Err(e) = r2
            && !e.is_cancelled()
        {
            tracing::warn!(error = %snafu::Report::from_error(&e), "reverse relay task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{MockWebTransportSession as TestSession, stream_pair as make_half};
    use h3x::{stream_id::StreamId, varint::VarInt};

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

    #[test]
    fn bind_candidates_expand_loopback_and_wildcard_semantics() {
        assert_eq!(
            bind_candidates("localhost"),
            vec![
                std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)),
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
            ]
        );
        assert_eq!(
            bind_candidates(""),
            vec![
                std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
                std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            ]
        );
    }

    #[test]
    fn explicit_single_family_bind_candidates_stay_single_family() {
        assert_eq!(
            bind_candidates("127.0.0.1"),
            vec![std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                0
            ))]
        );
        assert_eq!(
            bind_candidates("::"),
            vec![std::net::SocketAddr::from((
                std::net::Ipv6Addr::UNSPECIFIED,
                0
            ))]
        );
    }

    #[tokio::test]
    async fn localhost_listener_group_uses_one_logical_port() {
        let listener = bind_tcp_forward_group("localhost", 0).await.unwrap();
        assert_eq!(listener.advertised_host(), "localhost");
        assert_ne!(listener.bound_port(), 0);
        assert!(!listener.listeners.is_empty());
        for concrete in &listener.listeners {
            assert_eq!(concrete.local_addr().unwrap().port(), listener.bound_port());
        }
    }

    #[tokio::test]
    async fn tcp_forward_bind_and_cancel_stops_new_accepts() {
        let relays = TaskTracker::new();
        let relay_cancel = CancellationToken::new();
        let conv = make_conversation(make_test_session());

        let listener = TcpForwardListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.bound_port();
        assert_ne!(port, 0, "should get a real port");

        let handle = tokio::spawn(listener.run(conv, relays, relay_cancel));
        handle.abort();
        let _ = handle.await;

        for _ in 0..20 {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::AddrNotAvailable
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return;
                }
                Ok(stream) => {
                    drop(stream);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected connect error after cancel: {error}"),
            }
        }

        panic!("listener still accepted new TCP connections after cancel");
    }

    #[tokio::test]
    async fn tcp_connection_triggers_open_channel() {
        use h3x::codec::DecodeExt;
        use tokio::io::AsyncWriteExt;

        let relays = TaskTracker::new();
        let relay_cancel = CancellationToken::new();
        let session = make_test_session();
        let conv = make_conversation(session.clone());

        let listener = TcpForwardListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.bound_addr().port();
        let handle = tokio::spawn(listener.run(Arc::clone(&conv), relays, relay_cancel));

        let stream_id = VarInt::from_u32(44);
        let (remote_rd, local_wr) = make_half(stream_id);
        let (local_rd, remote_wr) = make_half(stream_id);
        session.provide_open_stream(local_rd, local_wr);

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tcp.write_all(b"hello").await.unwrap();

        let mut remote_rd = remote_rd;
        let mut remote_wr = remote_wr;

        let stream_kind: VarInt = remote_rd.decode_one().await.unwrap();
        assert_eq!(stream_kind, crate::webtransport::DSHELL_CHANNEL_STREAM_KIND);
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let connected_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let connected_port: VarInt = remote_rd.decode_one().await.unwrap();
        assert_eq!(&*connected_addr, "127.0.0.1");
        assert_eq!(connected_port, VarInt::from_u32(port as u32));
        let _orig_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _orig_port: VarInt = remote_rd.decode_one().await.unwrap();

        use h3x::codec::EncodeExt;
        remote_wr.encode_one(VarInt::from_u32(91)).await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap();
        remote_wr.flush().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert!(
            session.open_called(),
            "should have called open_stream via Conversation::open_channel"
        );

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn unix_forward_bind_and_cancel_stops_new_accepts_and_cleans_up_socket() {
        let relays = TaskTracker::new();
        let relay_cancel = CancellationToken::new();
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let conv = make_conversation(make_test_session());

        let listener = UnixForwardListener::bind(&sock_path).unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        let sock_path_clone = sock_path.clone();
        let handle = tokio::spawn(listener.run(conv, relays, relay_cancel));

        handle.abort();
        let _ = handle.await;

        tokio::task::yield_now().await;
        assert!(
            !sock_path_clone.exists(),
            "socket file should be cleaned up on cancel"
        );

        let error = tokio::net::UnixStream::connect(&sock_path_clone)
            .await
            .expect_err("unix listener should stop accepting after cancel");
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
            ),
            "unexpected unix connect error after cancel: {error}",
        );
    }

    #[tokio::test]
    async fn aborting_listener_task_keeps_established_tcp_forward_relay_alive() {
        use h3x::codec::{DecodeExt, EncodeExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::{sync::CancellationToken, task::TaskTracker};

        let session = make_test_session();
        let conv = make_conversation(session.clone());
        let listener = TcpForwardListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.bound_port();
        let relays = TaskTracker::new();
        let relay_cancel = CancellationToken::new();

        let stream_id = VarInt::from_u32(60);
        let (mut remote_rd, local_wr) = make_half(stream_id);
        let (local_rd, mut remote_wr) = make_half(stream_id);
        session.provide_open_stream(local_rd, local_wr);

        let handle =
            tokio::spawn(listener.run(Arc::clone(&conv), relays.clone(), relay_cancel.clone()));

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let _stream_kind: VarInt = remote_rd.decode_one().await.unwrap();
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _connected_port: VarInt = remote_rd.decode_one().await.unwrap();
        let _originator_addr: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _originator_port: VarInt = remote_rd.decode_one().await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(91)).await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap();
        remote_wr.flush().await.unwrap();

        handle.abort();
        let _ = handle.await;

        tcp.write_all(b"still-alive").await.unwrap();
        let mut buf = [0u8; 11];
        remote_rd.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"still-alive");

        relay_cancel.cancel();
        relays.close();
        relays.wait().await;
    }

    #[tokio::test]
    async fn aborting_listener_task_keeps_established_unix_forward_relay_alive() {
        use h3x::codec::{DecodeExt, EncodeExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::{sync::CancellationToken, task::TaskTracker};

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("relay.sock");
        let session = make_test_session();
        let conv = make_conversation(session.clone());
        let listener = UnixForwardListener::bind(&sock_path).unwrap();
        let relays = TaskTracker::new();
        let relay_cancel = CancellationToken::new();

        let stream_id = VarInt::from_u32(62);
        let (mut remote_rd, local_wr) = make_half(stream_id);
        let (local_rd, mut remote_wr) = make_half(stream_id);
        session.provide_open_stream(local_rd, local_wr);

        let handle =
            tokio::spawn(listener.run(Arc::clone(&conv), relays.clone(), relay_cancel.clone()));

        let mut unix = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let _stream_kind: VarInt = remote_rd.decode_one().await.unwrap();
        let _max_msg: VarInt = remote_rd.decode_one().await.unwrap();
        let _channel_type: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _socket_path: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        let _reserved: crate::codec::SshString = remote_rd.decode_one().await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(91)).await.unwrap();
        remote_wr.encode_one(VarInt::from_u32(32768)).await.unwrap();
        remote_wr.flush().await.unwrap();

        handle.abort();
        let _ = handle.await;

        unix.write_all(b"still-alive").await.unwrap();
        let mut buf = [0u8; 11];
        remote_rd.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"still-alive");

        relay_cancel.cancel();
        relays.close();
        relays.wait().await;
    }

    #[tokio::test]
    async fn drop_cleans_up_unix() {
        let relays = TaskTracker::new();
        let relay_cancel = CancellationToken::new();
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("drop-test.sock");

        let conv = make_conversation(make_test_session());

        let listener = UnixForwardListener::bind(&sock_path).unwrap();
        assert!(sock_path.exists(), "socket file should exist after bind");

        let handle = tokio::spawn(listener.run(conv, relays, relay_cancel));
        handle.abort();
        let _ = handle.await;

        tokio::task::yield_now().await;
        assert!(
            !sock_path.exists(),
            "socket file should be cleaned up on drop"
        );
    }
}
