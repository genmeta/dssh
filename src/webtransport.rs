//! DSSH over WebTransport stream adaptation.
//!
//! A WebTransport session provides bidirectional streams. DSSH reserves the
//! first field on each WebTransport bidirectional stream for a DSSH stream kind:
//!
//! - [`DSSH_CONTROL_STREAM_KIND`] — the conversation control stream
//! - [`DSSH_CHANNEL_STREAM_KIND`] — SSH channel streams managed by
//!   [`ManageSessionStream`](crate::conversation::ManageSessionStream)
//!
//! The WebTransport CONNECT stream is not used as a DSSH control stream. The
//! control stream is an ordinary WebTransport bidirectional stream marked with
//! the control kind.

use std::convert::Infallible;

use bytes::Bytes;
use h3x::{
    codec::{DecodeExt, EncodeExt, SinkWriter, StreamReader},
    quic,
    varint::VarInt,
};
use http::{HeaderValue, header::AUTHORIZATION, uri::Authority};
use http_body_util::{BodyExt, Empty};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use tokio::io::AsyncWriteExt;

use crate::constants::{SSH_VERSION, SSH3_CONNECT_PATH};
use crate::conversation::{Conversation, ManageSessionStream};
use crate::error::NegotiateVersionError;
use crate::version::{SshVersion, negotiate_version, version_response_header};

/// DSSH-over-WebTransport stream kind for the conversation control stream.
pub const DSSH_CONTROL_STREAM_KIND: VarInt = VarInt::from_u32(0);

/// DSSH-over-WebTransport stream kind for SSH channel streams.
pub const DSSH_CHANNEL_STREAM_KIND: VarInt = VarInt::from_u32(1);

/// Stream manager backed by a WebTransport session.
///
/// `open_stream` / `accept_stream` implement SSH channel stream management.
/// The control stream is handled explicitly through [`Self::open_control`] and
/// [`Self::accept_control`].
#[derive(Debug)]
pub struct WebTransportStreamManager<S> {
    session: S,
}

/// DSSH conversation backed by a WebTransport session.
pub type WebTransportConversation<S> = Conversation<
    WebTransportStreamManager<S>,
    StreamReader<<S as h3x::webtransport::Session>::StreamReader>,
    SinkWriter<<S as h3x::webtransport::Session>::StreamWriter>,
>;

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

impl<S> WebTransportStreamManager<S> {
    pub fn new(session: S) -> Self {
        Self { session }
    }

    pub fn into_inner(self) -> S {
        self.session
    }

    pub fn session(&self) -> &S {
        &self.session
    }
}

impl<S> WebTransportStreamManager<S>
where
    S: h3x::webtransport::Session,
    S::StreamReader: Unpin,
    S::StreamWriter: Unpin,
{
    /// Open the DSSH control stream on this WebTransport session.
    pub async fn open_control(
        &self,
    ) -> Result<(StreamReader<S::StreamReader>, SinkWriter<S::StreamWriter>), WebTransportStreamError>
    {
        let (reader, writer) = self
            .session
            .open_bi()
            .await
            .context(web_transport_stream_error::OpenBiSnafu)?;
        let writer = write_stream_kind(writer, DSSH_CONTROL_STREAM_KIND).await?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    /// Accept the DSSH control stream on this WebTransport session.
    pub async fn accept_control(
        &self,
    ) -> Result<(StreamReader<S::StreamReader>, SinkWriter<S::StreamWriter>), WebTransportStreamError>
    {
        self.accept_kind(DSSH_CONTROL_STREAM_KIND).await
    }

    async fn accept_kind(
        &self,
        expected: VarInt,
    ) -> Result<(StreamReader<S::StreamReader>, SinkWriter<S::StreamWriter>), WebTransportStreamError>
    {
        let (reader, writer) = self
            .session
            .accept_bi()
            .await
            .context(web_transport_stream_error::AcceptBiSnafu)?;
        let mut reader = StreamReader::new(reader);
        let actual = reader
            .decode_one::<VarInt>()
            .await
            .context(web_transport_stream_error::DecodeStreamKindSnafu)?;
        if actual != expected {
            return Err(WebTransportStreamError::UnexpectedStreamKind { kind: actual });
        }
        Ok((reader, SinkWriter::new(writer)))
    }
}

impl<S> ManageSessionStream for WebTransportStreamManager<S>
where
    S: h3x::webtransport::Session,
    S::StreamReader: Unpin,
    S::StreamWriter: Unpin,
{
    type StreamReader = StreamReader<S::StreamReader>;
    type StreamWriter = SinkWriter<S::StreamWriter>;
    type Error = WebTransportStreamError;

    async fn open_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        let (reader, writer) = self
            .session
            .open_bi()
            .await
            .context(web_transport_stream_error::OpenBiSnafu)?;
        let writer = write_stream_kind(writer, DSSH_CHANNEL_STREAM_KIND).await?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    async fn accept_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        self.accept_kind(DSSH_CHANNEL_STREAM_KIND).await
    }
}

/// Error returned when opening a DSSH conversation over WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum OpenConversationError {
    #[snafu(display("failed to open dssh webtransport control stream"))]
    OpenControl { source: WebTransportStreamError },
}

/// Error returned when accepting a DSSH conversation over WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum AcceptConversationError {
    #[snafu(display("failed to accept dssh webtransport control stream"))]
    AcceptControl { source: WebTransportStreamError },
}

/// Open a DSSH conversation on a WebTransport session.
///
/// The client side opens an ordinary WebTransport bidirectional stream, writes
/// [`DSSH_CONTROL_STREAM_KIND`] as the first field, then uses that stream as the
/// DSSH conversation control stream. Additional SSH channel streams are managed
/// by the returned [`WebTransportStreamManager`].
pub async fn open_conversation<S>(
    session: S,
    peer_version: impl Into<String>,
) -> Result<WebTransportConversation<S>, OpenConversationError>
where
    S: h3x::webtransport::Session,
    S::StreamReader: Unpin,
    S::StreamWriter: Unpin,
{
    let id = session.id();
    let manager = WebTransportStreamManager::new(session);
    let (reader, writer) = manager
        .open_control()
        .await
        .context(open_conversation_error::OpenControlSnafu)?;
    Ok(Conversation::new(id, peer_version, reader, writer, manager))
}

/// Accept a DSSH conversation on a WebTransport session.
///
/// The server side waits for an ordinary WebTransport bidirectional stream
/// whose first field is [`DSSH_CONTROL_STREAM_KIND`], then uses that stream as
/// the DSSH conversation control stream. Additional SSH channel streams are
/// managed by the returned [`WebTransportStreamManager`].
pub async fn accept_conversation<S>(
    session: S,
    peer_version: impl Into<String>,
) -> Result<WebTransportConversation<S>, AcceptConversationError>
where
    S: h3x::webtransport::Session,
    S::StreamReader: Unpin,
    S::StreamWriter: Unpin,
{
    let id = session.id();
    let manager = WebTransportStreamManager::new(session);
    let (reader, writer) = manager
        .accept_control()
        .await
        .context(accept_conversation_error::AcceptControlSnafu)?;
    Ok(Conversation::new(id, peer_version, reader, writer, manager))
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
        source: h3x::hyper::client::RequestError<Infallible>,
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
/// HTTP `Authorization` header.
pub fn client_connect_request(
    authority: &Authority,
    authorization: Option<HeaderValue>,
) -> Result<http::Request<Empty<Bytes>>, BuildClientConnectRequestError> {
    let uri = format!("https://{authority}{SSH3_CONNECT_PATH}")
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
    authorization: Option<HeaderValue>,
) -> Result<ClientWebTransportConversation, ClientConnectConversationError>
where
    C: h3x::quic::Connection,
{
    let request = client_connect_request(authority, authorization)
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
    open_conversation(session, peer_version.version_string)
        .await
        .context(client_connect_conversation_error::OpenConversationSnafu)
}

/// Accept a DSSH WebTransport Extended CONNECT request after the caller has
/// already made its authentication and authorization decision.
///
/// The returned HTTP response must be sent back to the peer. Only after that
/// response is on the wire should the server call [`accept_conversation`] in a
/// task that owns the returned session; otherwise client and server can
/// deadlock waiting for each other.
pub async fn accept_server_session<B>(
    request: http::Request<B>,
) -> Result<AcceptedWebTransportSession, AcceptServerSessionError>
where
    B: http_body::Body + Unpin + Send + 'static,
{
    ensure!(
        request.uri().path() == SSH3_CONNECT_PATH,
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

/// Error returned by [`WebTransportStreamManager`] operations.
#[derive(Debug, Snafu)]
#[snafu(module)]
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

async fn write_stream_kind<W>(writer: W, kind: VarInt) -> Result<W, WebTransportStreamError>
where
    W: quic::WriteStream + Unpin,
{
    let mut writer = SinkWriter::new(writer);
    writer
        .encode_one(kind)
        .await
        .context(web_transport_stream_error::EncodeStreamKindSnafu)?;
    AsyncWriteExt::flush(&mut writer)
        .await
        .context(web_transport_stream_error::FlushStreamKindSnafu)?;
    Ok(writer.into_inner())
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
    use futures::{Sink, SinkExt, Stream};
    use h3x::{
        quic::{CancelStream, GetStreamId, StopStream},
        stream_id::StreamId,
    };
    use http::HeaderMap;
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::constants::SSH_VERSION;

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

    impl CancelStream for TestWriteStream {
        fn poll_cancel(
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

        fn id(&self) -> StreamId {
            StreamId(VarInt::from_u32(4))
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
            unreachable!("dssh webtransport manager uses only bidirectional streams")
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
            unreachable!("dssh webtransport manager uses only bidirectional streams")
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
    async fn open_control_and_channel_prefix_stream_kind() {
        let session = TestSession::default();
        let manager = WebTransportStreamManager::new(session);

        manager.open_control().await.expect("open control");
        assert_eq!(manager.session().open_state.written(), vec![0]);

        manager.open_stream().await.expect("open channel");
        assert_eq!(manager.session().open_state.written(), vec![0, 1]);
    }

    #[tokio::test]
    async fn accept_control_consumes_control_kind_and_leaves_payload() {
        let session = TestSession::with_accept_bytes(b"\x00hello");
        let manager = WebTransportStreamManager::new(session);

        let (mut reader, _writer) = manager.accept_control().await.expect("accept control");
        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .await
            .expect("read payload");

        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn accept_stream_consumes_channel_kind_and_leaves_payload() {
        let session = TestSession::with_accept_bytes(b"\x01payload");
        let manager = WebTransportStreamManager::new(session);

        let (mut reader, _writer) = manager.accept_stream().await.expect("accept channel");
        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .await
            .expect("read payload");

        assert_eq!(payload, b"payload");
    }

    #[tokio::test]
    async fn accept_stream_rejects_unexpected_kind() {
        let session = TestSession::with_accept_bytes(b"\x00control");
        let manager = WebTransportStreamManager::new(session);

        let error = match manager.accept_stream().await {
            Ok(_) => panic!("control stream is not a channel stream"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            WebTransportStreamError::UnexpectedStreamKind { kind }
                if kind == DSSH_CONTROL_STREAM_KIND
        ));
    }

    #[tokio::test]
    async fn accepted_writer_remains_usable_after_kind_decode() {
        let session = TestSession::with_accept_bytes(b"\x01");
        let manager = WebTransportStreamManager::new(session);

        let (_reader, mut writer) = manager.accept_stream().await.expect("accept channel");
        writer
            .send(Bytes::from_static(b"reply"))
            .await
            .expect("write reply");
        SinkExt::flush(&mut writer).await.expect("flush reply");
    }

    #[tokio::test]
    async fn decode_kind_error_is_structured() {
        let session = TestSession::with_accept_bytes(b"");
        let manager = WebTransportStreamManager::new(session);

        let error = match manager.accept_control().await {
            Ok(_) => panic!("empty stream cannot carry kind"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            WebTransportStreamError::DecodeStreamKind { .. }
        ));
    }

    #[tokio::test]
    async fn accept_empty_session_preserves_closed_accept_error() {
        let session = TestSession::default();
        let manager = WebTransportStreamManager::new(session);

        let error = match manager.accept_stream().await {
            Ok(_) => panic!("empty session cannot accept a channel stream"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            WebTransportStreamError::AcceptBi {
                source: h3x::webtransport::AcceptStreamError::Closed { .. }
            }
        ));
    }

    #[tokio::test]
    async fn open_conversation_opens_control_stream_and_preserves_metadata() {
        let session = TestSession::default();
        let open_state = session.open_state.clone();

        let conversation = open_conversation(session, SSH_VERSION)
            .await
            .expect("conversation opens");

        assert_eq!(conversation.id(), StreamId(VarInt::from_u32(4)));
        assert_eq!(conversation.peer_version(), SSH_VERSION);
        assert_eq!(open_state.written(), vec![0]);
    }

    #[tokio::test]
    async fn accept_conversation_accepts_control_stream_and_preserves_metadata() {
        let session = TestSession::with_accept_bytes(b"\x00control");

        let conversation = accept_conversation(session, SSH_VERSION)
            .await
            .expect("conversation accepts");

        assert_eq!(conversation.id(), StreamId(VarInt::from_u32(4)));
        assert_eq!(conversation.peer_version(), SSH_VERSION);
    }

    #[tokio::test]
    async fn accept_conversation_rejects_channel_stream_as_control() {
        let session = TestSession::with_accept_bytes(b"\x01channel");

        let error = match accept_conversation(session, SSH_VERSION).await {
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
    fn client_connect_request_uses_webtransport_protocol_and_version() {
        let authority: Authority = "example.test:443".parse().expect("authority");
        let authorization = HeaderValue::from_static("Basic abc");

        let request = client_connect_request(&authority, Some(authorization.clone()))
            .expect("request builds");

        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(
            request.uri().to_string(),
            format!("https://{authority}{SSH3_CONNECT_PATH}")
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

        let error = match accept_server_session(request).await {
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
            .uri(format!("https://example.test{SSH3_CONNECT_PATH}"))
            .body(Empty::<Bytes>::new())
            .expect("request");

        let error = match accept_server_session(request).await {
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
