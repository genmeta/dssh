//! DSSH over WebTransport stream adaptation.
//!
//! A WebTransport session provides bidirectional streams. DSSH reserves the
//! first field on each WebTransport bidirectional stream for a DSSH stream kind:
//!
//! - [`DSSH_CONTROL_STREAM_KIND`] — the conversation control stream
//! - [`DSSH_CHANNEL_STREAM_KIND`] — SSH channel streams managed by
//!   [`Conversation`](crate::conversation::Conversation)
//!
//! The WebTransport CONNECT stream is not used as a DSSH control stream. The
//! control stream is an ordinary WebTransport bidirectional stream marked with
//! the control kind.

use std::convert::Infallible;

use bytes::Bytes;
use h3x::varint::VarInt;
use http::{HeaderValue, header::AUTHORIZATION, uri::Authority};
use http_body_util::{BodyExt, Empty};
use snafu::{OptionExt, ResultExt, Snafu, ensure};

use crate::constants::SSH_VERSION;
use crate::conversation::Conversation;
use crate::error::NegotiateVersionError;
use crate::version::{SshVersion, negotiate_version, version_response_header};

/// DSSH-over-WebTransport stream kind for the conversation control stream.
pub const DSSH_CONTROL_STREAM_KIND: VarInt = VarInt::from_u32(0);

/// DSSH-over-WebTransport stream kind for SSH channel streams.
pub const DSSH_CHANNEL_STREAM_KIND: VarInt = VarInt::from_u32(1);

/// DSSH conversation backed by a WebTransport session.
pub type WebTransportConversation<S> = Conversation<S>;

/// DSSH conversation backed by a concrete h3x WebTransport session.
pub type ClientWebTransportConversation =
    WebTransportConversation<h3x::webtransport::WebTransportSession>;

/// Accepted server-side WebTransport session plus the HTTP response that must
/// be returned to complete the Extended CONNECT handshake.
pub struct AcceptedWebTransportSession {
    pub response: http::Response<Empty<Bytes>>,
    pub session: h3x::webtransport::WebTransportSession,
    pub peer_version: String,
}

/// Error returned when opening a DSSH conversation over WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum OpenConversationError {
    #[snafu(display("failed to open dssh webtransport control stream"))]
    OpenControl { source: WebTransportStreamError },
}

/// Error returned when accepting a DSSH conversation over WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum AcceptConversationError {
    #[snafu(display("failed to accept dssh webtransport control stream"))]
    AcceptControl { source: WebTransportStreamError },
}

/// Error returned when constructing a client-side DSSH WebTransport CONNECT
/// request.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum BuildClientConnectRequestError {
    #[snafu(display("failed to build dssh webtransport connect URI"))]
    Uri { source: http::uri::InvalidUri },
    #[snafu(display("failed to build dssh webtransport connect request"))]
    Request { source: http::Error },
}

/// Error returned when opening a client-side DSSH conversation over
/// WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ClientConnectConversationError {
    #[snafu(display("failed to build dssh webtransport connect request"))]
    BuildRequest {
        source: BuildClientConnectRequestError,
    },
    #[snafu(display("failed to execute dssh webtransport connect request"))]
    Execute {
        source: h3x::hyper::RequestError<Infallible>,
    },
    #[snafu(display("failed to validate dssh peer version"))]
    PeerVersion { source: NegotiateVersionError },
    #[snafu(display("failed to establish extended connect"))]
    Establish {
        source: h3x::hyper::extended_connect::EstablishError,
    },
    #[snafu(display("successful dssh webtransport connect response was not validated"))]
    MissingValidatedPeerVersion,
    #[snafu(display("failed to register webtransport session"))]
    RegisterSession {
        source: h3x::webtransport::RegisterSessionError,
    },
    #[snafu(display("failed to open dssh webtransport conversation"))]
    OpenConversation { source: OpenConversationError },
}

/// Error returned when accepting a server-side DSSH WebTransport session from
/// an Extended CONNECT request.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum AcceptServerSessionError {
    #[snafu(display("extended connect path {path} is not the dssh connect path"))]
    UnexpectedPath { path: String },
    #[snafu(display("failed to validate dssh peer version"))]
    PeerVersion { source: NegotiateVersionError },
    #[snafu(display("failed to accept extended connect"))]
    Accept {
        source: h3x::hyper::extended_connect::AcceptError,
    },
    #[snafu(display("failed to register webtransport session"))]
    RegisterSession {
        source: h3x::webtransport::RegisterSessionError,
    },
}

/// Build a DSSH WebTransport Extended CONNECT request.
///
/// The returned request carries `:protocol = webtransport-h3` through h3x's
/// [`h3x::qpack::field::Protocol`] extension and includes the DSSH
/// `ssh-version` header. Authentication, when present, is carried as a normal
/// HTTP `Authorization` header. `path` is supplied by the caller so gateways
/// can keep their routed SSH location, while clients that want a stable
/// well-known endpoint can pass
/// [`DSSH_CONNECT_PATH`](crate::constants::DSSH_CONNECT_PATH).
pub fn client_connect_request(
    authority: &Authority,
    path: &str,
    authorization: Option<HeaderValue>,
) -> Result<http::Request<Empty<Bytes>>, BuildClientConnectRequestError> {
    let uri = format!("https://{authority}{path}")
        .parse::<http::Uri>()
        .context(build_client_connect_request_error::UriSnafu)?;

    let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("ssh-version", SSH_VERSION)
        .extension(h3x::qpack::field::Protocol::new(
            h3x::webtransport::WEBTRANSPORT_H3,
        ));
    if let Some(value) = authorization {
        builder = builder.header(AUTHORIZATION, value);
    }

    builder
        .body(Empty::<Bytes>::new())
        .context(build_client_connect_request_error::RequestSnafu)
}

fn peer_version(headers: &http::HeaderMap) -> Result<SshVersion, NegotiateVersionError> {
    negotiate_version(headers)
}

/// Send a DSSH WebTransport Extended CONNECT request and open the DSSH
/// conversation control stream on the resulting WebTransport session.
pub async fn open_client_conversation<C>(
    connection: &h3x::connection::Connection<C>,
    authority: &Authority,
    path: &str,
    authorization: Option<HeaderValue>,
) -> Result<ClientWebTransportConversation, ClientConnectConversationError>
where
    C: h3x::quic::Connection,
{
    let request = client_connect_request(authority, path, authorization)
        .context(client_connect_conversation_error::BuildRequestSnafu)?;
    let response = connection
        .execute_hyper_request(request)
        .await
        .context(client_connect_conversation_error::ExecuteSnafu)?;
    let peer_version = if response.status().is_success() {
        Some(
            peer_version(response.headers())
                .context(client_connect_conversation_error::PeerVersionSnafu)?,
        )
    } else {
        None
    };
    let connect = h3x::hyper::extended_connect::establish(response.map(|body| body.boxed_unsync()))
        .await
        .context(client_connect_conversation_error::EstablishSnafu)?;
    let peer_version = peer_version
        .context(client_connect_conversation_error::MissingValidatedPeerVersionSnafu)?;
    let session = h3x::webtransport::WebTransportSession::try_from(connect)
        .context(client_connect_conversation_error::RegisterSessionSnafu)?;
    Conversation::open(session, peer_version.version_string)
        .await
        .context(client_connect_conversation_error::OpenConversationSnafu)
}

/// Accept a DSSH WebTransport Extended CONNECT request after the caller has
/// already made its authentication and authorization decision.
///
/// The accepted request path must match `path`. This keeps route ownership with
/// the server or gateway layer instead of forcing every deployment to use the
/// well-known DSSH path.
///
/// The returned HTTP response must be sent back to the peer. Only after that
/// response is on the wire should the server call [`Conversation::accept`] in a
/// task that owns the returned session; otherwise client and server can
/// deadlock waiting for each other.
pub async fn accept_server_session<B>(
    request: http::Request<B>,
    path: &str,
) -> Result<AcceptedWebTransportSession, AcceptServerSessionError>
where
    B: http_body::Body + Unpin + Send + 'static,
{
    ensure!(
        request.uri().path() == path,
        accept_server_session_error::UnexpectedPathSnafu {
            path: request.uri().path().to_owned(),
        }
    );
    let version =
        peer_version(request.headers()).context(accept_server_session_error::PeerVersionSnafu)?;
    let (mut response, connect) = h3x::hyper::extended_connect::accept(request)
        .await
        .context(accept_server_session_error::AcceptSnafu)?;
    let session = h3x::webtransport::WebTransportSession::try_from(connect)
        .context(accept_server_session_error::RegisterSessionSnafu)?;
    response
        .headers_mut()
        .insert("ssh-version", version_response_header(&version));

    Ok(AcceptedWebTransportSession {
        response,
        session,
        peer_version: version.version_string,
    })
}

/// Error returned by DSSH WebTransport stream-kind operations.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum WebTransportStreamError {
    #[snafu(display("failed to open webtransport bidirectional stream"))]
    OpenBi {
        source: h3x::webtransport::OpenStreamError,
    },

    #[snafu(display("failed to accept webtransport bidirectional stream"))]
    AcceptBi {
        source: h3x::webtransport::AcceptStreamError,
    },

    #[snafu(display("failed to encode dssh webtransport stream kind"))]
    EncodeStreamKind { source: std::io::Error },

    #[snafu(display("failed to flush dssh webtransport stream kind"))]
    FlushStreamKind { source: std::io::Error },

    #[snafu(display("failed to decode dssh webtransport stream kind"))]
    DecodeStreamKind { source: std::io::Error },

    #[snafu(display("unexpected dssh webtransport stream kind {kind}"))]
    UnexpectedStreamKind { kind: VarInt },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, Stream};
    use h3x::{
        quic::{self, GetStreamId, ResetStream, StopStream},
        stream_id::StreamId,
    };
    use http::HeaderMap;

    use super::*;
    use crate::constants::{DSSH_CONNECT_PATH, SSH_VERSION};

    #[derive(Debug, Default)]
    struct StreamState {
        written: Mutex<Vec<u8>>,
    }

    impl StreamState {
        fn written(&self) -> Vec<u8> {
            self.written.lock().expect("written lock poisoned").clone()
        }
    }

    #[derive(Debug)]
    struct TestReadStream {
        chunks: VecDeque<Bytes>,
        stream_id: VarInt,
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }

    impl GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        state: Arc<StreamState>,
        stream_id: VarInt,
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state
                .written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl ResetStream for TestWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct TestSession {
        open_state: Arc<StreamState>,
        accept_streams: Mutex<VecDeque<(TestReadStream, TestWriteStream)>>,
    }

    impl TestSession {
        fn with_accept_bytes(bytes: &'static [u8]) -> Self {
            let session = Self::default();
            session
                .accept_streams
                .lock()
                .expect("accept lock poisoned")
                .push_back(stream_pair_with_read(bytes, VarInt::from_u32(7)));
            session
        }
    }

    impl h3x::webtransport::Session for TestSession {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        fn id(&self) -> h3x::webtransport::WebTransportSessionId {
            h3x::webtransport::WebTransportSessionId::try_from(StreamId(VarInt::from_u32(4)))
                .expect("test session id must be client-initiated bidirectional")
        }

        async fn drain(&self) -> Result<(), h3x::webtransport::DrainSessionError> {
            Ok(())
        }

        async fn close(
            &self,
            _close: h3x::webtransport::CloseSession,
        ) -> Result<(), h3x::webtransport::CloseSessionError> {
            Ok(())
        }

        async fn drained(&self) -> h3x::webtransport::SessionDrain {
            h3x::webtransport::SessionDrain::Closed(self.closed().await)
        }

        async fn closed(&self) -> h3x::webtransport::CloseReason {
            h3x::webtransport::CloseReason::Session(
                h3x::webtransport::SessionCloseReason::ControlStreamError,
            )
        }

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), h3x::webtransport::OpenStreamError>
        {
            Ok((
                TestReadStream {
                    chunks: VecDeque::new(),
                    stream_id: VarInt::from_u32(5),
                },
                TestWriteStream {
                    state: self.open_state.clone(),
                    stream_id: VarInt::from_u32(5),
                },
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, h3x::webtransport::OpenStreamError> {
            unreachable!("dssh webtransport conversation uses only bidirectional streams")
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), h3x::webtransport::AcceptStreamError>
        {
            self.accept_streams
                .lock()
                .expect("accept lock poisoned")
                .pop_front()
                .ok_or(h3x::webtransport::AcceptStreamError::Closed {
                    source: h3x::webtransport::SessionClosed,
                })
        }

        async fn accept_uni(
            &self,
        ) -> Result<Self::StreamReader, h3x::webtransport::AcceptStreamError> {
            unreachable!("dssh webtransport conversation uses only bidirectional streams")
        }
    }

    fn stream_pair_with_read(
        bytes: &'static [u8],
        stream_id: VarInt,
    ) -> (TestReadStream, TestWriteStream) {
        let state = Arc::new(StreamState::default());
        (
            TestReadStream {
                chunks: VecDeque::from([Bytes::from_static(bytes)]),
                stream_id,
            },
            TestWriteStream { state, stream_id },
        )
    }

    #[tokio::test]
    async fn open_conversation_opens_control_stream_and_preserves_metadata() {
        let session = TestSession::default();
        let open_state = session.open_state.clone();

        let conversation = Conversation::open(session, SSH_VERSION)
            .await
            .expect("conversation opens");

        assert_eq!(conversation.id(), StreamId(VarInt::from_u32(4)));
        assert_eq!(conversation.peer_version(), SSH_VERSION);
        assert_eq!(open_state.written(), vec![0]);
    }

    #[tokio::test]
    async fn accept_conversation_accepts_control_stream_and_preserves_metadata() {
        let session = TestSession::with_accept_bytes(b"\x00control");

        let conversation = Conversation::accept(session, SSH_VERSION)
            .await
            .expect("conversation accepts");

        assert_eq!(conversation.id(), StreamId(VarInt::from_u32(4)));
        assert_eq!(conversation.peer_version(), SSH_VERSION);
    }

    #[tokio::test]
    async fn accept_conversation_rejects_channel_stream_as_control() {
        let session = TestSession::with_accept_bytes(b"\x01channel");

        let error = match Conversation::accept(session, SSH_VERSION).await {
            Ok(_) => panic!("channel stream is not a control stream"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            AcceptConversationError::AcceptControl {
                source: WebTransportStreamError::UnexpectedStreamKind { kind }
            } if kind == DSSH_CHANNEL_STREAM_KIND
        ));
    }

    #[test]
    fn dssh_connect_path_is_well_known_dssh_path() {
        assert_eq!(DSSH_CONNECT_PATH, "/.well-known/dssh/connect");
    }

    #[test]
    fn client_connect_request_uses_custom_path_webtransport_protocol_and_version() {
        let authority: Authority = "example.test:443".parse().expect("authority");
        let authorization = HeaderValue::from_static("Basic abc");
        let path = "/ssh/yiyue";

        let request = client_connect_request(&authority, path, Some(authorization.clone()))
            .expect("request builds");

        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.uri().to_string(),
            format!("https://{authority}{path}")
        );
        assert_eq!(
            request.headers().get("ssh-version"),
            Some(&HeaderValue::from_static(SSH_VERSION))
        );
        assert_eq!(request.headers().get(AUTHORIZATION), Some(&authorization));
        assert_eq!(
            request
                .extensions()
                .get::<h3x::qpack::field::Protocol>()
                .map(h3x::qpack::field::Protocol::as_str),
            Some(h3x::webtransport::WEBTRANSPORT_H3)
        );
    }

    #[test]
    fn peer_version_rejects_missing_invalid_and_unsupported_values() {
        let headers = HeaderMap::new();
        assert!(matches!(
            peer_version(&headers),
            Err(NegotiateVersionError::MissingSshVersionHeader)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            "ssh-version",
            HeaderValue::from_bytes(b"dssh-00\xff").expect("opaque header value"),
        );
        assert!(matches!(
            peer_version(&headers),
            Err(NegotiateVersionError::InvalidSshVersionHeaderValue { .. })
        ));

        let mut headers = HeaderMap::new();
        headers.insert("ssh-version", HeaderValue::from_static("dssh-99"));
        assert!(matches!(
            peer_version(&headers),
            Err(NegotiateVersionError::UnsupportedSshVersion { offered }) if offered == "dssh-99"
        ));

        let mut headers = HeaderMap::new();
        headers.insert("ssh-version", HeaderValue::from_static(SSH_VERSION));
        assert_eq!(
            peer_version(&headers)
                .expect("supported version")
                .version_string,
            SSH_VERSION
        );
    }

    #[tokio::test]
    async fn accept_server_session_rejects_wrong_path_before_registering_session() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/not-dssh")
            .header("ssh-version", SSH_VERSION)
            .body(Empty::<Bytes>::new())
            .expect("request");

        let error = match accept_server_session(request, DSSH_CONNECT_PATH).await {
            Ok(_) => panic!("wrong path must not be accepted"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            AcceptServerSessionError::UnexpectedPath { path } if path == "/not-dssh"
        ));
    }

    #[tokio::test]
    async fn accept_server_session_rejects_missing_version_before_registering_session() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://example.test{DSSH_CONNECT_PATH}"))
            .body(Empty::<Bytes>::new())
            .expect("request");

        let error = match accept_server_session(request, DSSH_CONNECT_PATH).await {
            Ok(_) => panic!("missing version must not be accepted"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            AcceptServerSessionError::PeerVersion {
                source: NegotiateVersionError::MissingSshVersionHeader
            }
        ));
    }
}
