//! DShell over WebTransport stream adaptation.
//!
//! A WebTransport session provides bidirectional streams. DShell reserves the
//! first field on each WebTransport bidirectional stream for a DShell stream kind:
//!
//! - [`DSHELL_CONTROL_STREAM_KIND`] — the conversation control stream
//! - [`DSHELL_CHANNEL_STREAM_KIND`] — SSH channel streams managed by
//!   [`Conversation`](crate::conversation::Conversation)
//!
//! The WebTransport CONNECT stream is not used as a DShell control stream. The
//! control stream is an ordinary WebTransport bidirectional stream marked with
//! the control kind.

use std::convert::Infallible;

use bytes::Bytes;
use h3x::varint::VarInt;
use http::{HeaderValue, header::AUTHORIZATION, uri::Authority};
use http_body_util::{BodyExt, Empty};
use snafu::{OptionExt, ResultExt, Snafu, ensure};

use crate::constants::DSHELL_VERSION;
use crate::conversation::Conversation;
use crate::error::NegotiateVersionError;
use crate::version::{DshellVersion, negotiate_version, version_response_header};

/// DShell-over-WebTransport stream kind for the conversation control stream.
pub const DSHELL_CONTROL_STREAM_KIND: VarInt = VarInt::from_u32(0);

/// DShell-over-WebTransport stream kind for SSH channel streams.
pub const DSHELL_CHANNEL_STREAM_KIND: VarInt = VarInt::from_u32(1);

/// DShell conversation backed by a WebTransport session.
pub type WebTransportConversation<S> = Conversation<S>;

/// DShell conversation backed by a concrete h3x WebTransport session.
pub type ClientWebTransportConversation =
    WebTransportConversation<h3x::webtransport::WebTransportSession>;

/// Accepted server-side WebTransport session plus the HTTP response that must
/// be returned to complete the Extended CONNECT handshake.
pub struct AcceptedWebTransportSession {
    pub response: http::Response<Empty<Bytes>>,
    pub session: h3x::webtransport::WebTransportSession,
    pub peer_version: String,
}

/// Error returned when opening a DShell conversation over WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum OpenConversationError {
    #[snafu(display("failed to open dshell webtransport control stream"))]
    OpenControl { source: WebTransportStreamError },
}

/// Error returned when accepting a DShell conversation over WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum AcceptConversationError {
    #[snafu(display("failed to accept dshell webtransport control stream"))]
    AcceptControl { source: WebTransportStreamError },
}

/// Error returned when constructing a client-side DShell WebTransport CONNECT
/// request.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum BuildClientConnectRequestError {
    #[snafu(display("failed to build dshell webtransport connect URI"))]
    Uri { source: http::uri::InvalidUri },
    #[snafu(display("failed to build dshell webtransport connect request"))]
    Request { source: http::Error },
}

/// Error returned when opening a client-side DShell conversation over
/// WebTransport.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ClientConnectConversationError {
    #[snafu(display("failed to build dshell webtransport connect request"))]
    BuildRequest {
        source: BuildClientConnectRequestError,
    },
    #[snafu(display("failed to execute dshell webtransport connect request"))]
    Execute {
        source: h3x::hyper::RequestError<Infallible>,
    },
    #[snafu(display("failed to validate dshell peer version"))]
    PeerVersion { source: NegotiateVersionError },
    #[snafu(display("failed to establish extended connect"))]
    Establish {
        source: h3x::hyper::extended_connect::EstablishError,
    },
    #[snafu(display("successful dshell webtransport connect response was not validated"))]
    MissingValidatedPeerVersion,
    #[snafu(display("failed to register webtransport session"))]
    RegisterSession {
        source: h3x::webtransport::RegisterSessionError,
    },
    #[snafu(display("failed to open dshell webtransport conversation"))]
    OpenConversation { source: OpenConversationError },
}

/// Error returned when accepting a server-side DShell WebTransport session from
/// an Extended CONNECT request.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum AcceptServerSessionError {
    #[snafu(display("extended connect path {path} is not the dshell connect path"))]
    UnexpectedPath { path: String },
    #[snafu(display("failed to validate dshell peer version"))]
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

/// Build a DShell WebTransport Extended CONNECT request.
///
/// The returned request carries `:protocol = webtransport-h3` through h3x's
/// [`h3x::qpack::field::Protocol`] extension and includes the DShell
/// `ssh-version` header. Authentication, when present, is carried as a normal
/// HTTP `Authorization` header. `path` is supplied by the caller so gateways
/// can keep their routed SSH location, while clients that want a stable
/// well-known endpoint can pass
/// [`DSHELL_CONNECT_PATH`](crate::constants::DSHELL_CONNECT_PATH).
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
        .header("ssh-version", DSHELL_VERSION)
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

fn peer_version(headers: &http::HeaderMap) -> Result<DshellVersion, NegotiateVersionError> {
    negotiate_version(headers)
}

/// Send a DShell WebTransport Extended CONNECT request and open the DShell
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

/// Accept a DShell WebTransport Extended CONNECT request after the caller has
/// already made its authentication and authorization decision.
///
/// The accepted request path must match `path`. This keeps route ownership with
/// the server or gateway layer instead of forcing every deployment to use the
/// well-known DShell path.
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

/// Error returned by DShell WebTransport stream-kind operations.
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

    #[snafu(display("failed to encode dshell webtransport stream kind"))]
    EncodeStreamKind { source: std::io::Error },

    #[snafu(display("failed to flush dshell webtransport stream kind"))]
    FlushStreamKind { source: std::io::Error },

    #[snafu(display("failed to decode dshell webtransport stream kind"))]
    DecodeStreamKind { source: std::io::Error },

    #[snafu(display("unexpected dshell webtransport stream kind {kind}"))]
    UnexpectedStreamKind { kind: VarInt },
}

#[cfg(test)]
mod tests {
    use h3x::{codec::DecodeExt, stream_id::StreamId};
    use http::HeaderMap;

    use super::*;
    use crate::constants::{DSHELL_CONNECT_PATH, DSHELL_VERSION};
    use crate::test_support::{MockWebTransportSession as TestSession, stream_pair as make_half};

    fn test_session() -> TestSession {
        TestSession::new(StreamId(VarInt::from_u32(4)))
    }

    fn session_with_accept_bytes(bytes: &'static [u8]) -> TestSession {
        let session = test_session();
        session.provide_accept_bytes(VarInt::from_u32(8), Bytes::from_static(bytes));
        session
    }

    #[tokio::test]
    async fn open_conversation_opens_control_stream_and_preserves_metadata() {
        let session = test_session();
        let stream_id = VarInt::from_u32(8);
        let (local_reader, _remote_writer) = make_half(stream_id);
        let (mut remote_reader, local_writer) = make_half(stream_id);
        session.provide_open_stream(local_reader, local_writer);

        let conversation = Conversation::open(session, DSHELL_VERSION)
            .await
            .expect("conversation opens");

        let kind: VarInt = remote_reader.decode_one().await.expect("stream kind");
        assert_eq!(kind, DSHELL_CONTROL_STREAM_KIND);
        assert_eq!(conversation.id(), StreamId(VarInt::from_u32(4)));
        assert_eq!(conversation.peer_version(), DSHELL_VERSION);
    }

    #[tokio::test]
    async fn accept_conversation_accepts_control_stream_and_preserves_metadata() {
        let session = session_with_accept_bytes(b"\x00control");

        let conversation = Conversation::accept(session, DSHELL_VERSION)
            .await
            .expect("conversation accepts");

        assert_eq!(conversation.id(), StreamId(VarInt::from_u32(4)));
        assert_eq!(conversation.peer_version(), DSHELL_VERSION);
    }

    #[tokio::test]
    async fn accept_conversation_rejects_channel_stream_as_control() {
        let session = session_with_accept_bytes(b"\x01channel");

        let error = match Conversation::accept(session, DSHELL_VERSION).await {
            Ok(_) => panic!("channel stream is not a control stream"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            AcceptConversationError::AcceptControl {
                source: WebTransportStreamError::UnexpectedStreamKind { kind }
            } if kind == DSHELL_CHANNEL_STREAM_KIND
        ));
    }

    #[test]
    fn dshell_connect_path_is_well_known_dshell_path() {
        assert_eq!(DSHELL_CONNECT_PATH, "/.well-known/dshell/connect");
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
            Some(&HeaderValue::from_static(DSHELL_VERSION))
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
            Err(NegotiateVersionError::MissingDshellVersionHeader)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            "ssh-version",
            HeaderValue::from_bytes(b"dshell-00\xff").expect("opaque header value"),
        );
        assert!(matches!(
            peer_version(&headers),
            Err(NegotiateVersionError::InvalidDshellVersionHeaderValue { .. })
        ));

        let mut headers = HeaderMap::new();
        headers.insert("ssh-version", HeaderValue::from_static("dshell-99"));
        assert!(matches!(
            peer_version(&headers),
            Err(NegotiateVersionError::UnsupportedDshellVersion { offered }) if offered == "dshell-99"
        ));

        let mut headers = HeaderMap::new();
        headers.insert("ssh-version", HeaderValue::from_static(DSHELL_VERSION));
        assert_eq!(
            peer_version(&headers)
                .expect("supported version")
                .version_string,
            DSHELL_VERSION
        );
    }

    #[tokio::test]
    async fn accept_server_session_rejects_wrong_path_before_registering_session() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/not-dshell")
            .header("ssh-version", DSHELL_VERSION)
            .body(Empty::<Bytes>::new())
            .expect("request");

        let error = match accept_server_session(request, DSHELL_CONNECT_PATH).await {
            Ok(_) => panic!("wrong path must not be accepted"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            AcceptServerSessionError::UnexpectedPath { path } if path == "/not-dshell"
        ));
    }

    #[tokio::test]
    async fn accept_server_session_rejects_missing_version_before_registering_session() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://example.test{DSHELL_CONNECT_PATH}"))
            .body(Empty::<Bytes>::new())
            .expect("request");

        let error = match accept_server_session(request, DSHELL_CONNECT_PATH).await {
            Ok(_) => panic!("missing version must not be accepted"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            AcceptServerSessionError::PeerVersion {
                source: NegotiateVersionError::MissingDshellVersionHeader
            }
        ));
    }
}
