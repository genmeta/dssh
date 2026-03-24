//! SSH3 client: connect to an SSH3 server via Extended CONNECT.
//!
//! Provides [`Ssh3Client`] for establishing an SSH3 connection over HTTP/3.
//! The [`connect`](Ssh3Client::connect) method returns a
//! [`Conversation<ConversationHandle>`] directly.

use base64::engine::{Engine, general_purpose::STANDARD};
use h3x::qpack::field::Protocol;
use h3x::quic::GetStreamIdExt;
use h3x::stream_id::StreamId;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::{ResultExt, Snafu};

use crate::constants::SSH_VERSION;
use crate::conversation::Conversation;
use crate::protocol::{ConversationHandle, RegisterError, Ssh3Protocol};

/// Well-known path for SSH3 Extended CONNECT requests.
pub const SSH3_CONNECT_PATH: &str = "/.well-known/ssh3/connect";

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum ConnectError {
    #[snafu(display("invalid authority"))]
    InvalidAuthority { source: http::uri::InvalidUri },

    #[snafu(display("failed to establish QUIC connection"))]
    QuicConnect {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("invalid URI"))]
    InvalidUri { source: http::uri::InvalidUri },

    #[snafu(display("failed to build HTTP request"))]
    RequestBuild { source: http::Error },

    #[snafu(display("Extended CONNECT request failed"))]
    ConnectRequest {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("authentication failed (HTTP 401)"))]
    AuthenticationFailed,

    #[snafu(display("unexpected HTTP status: {status}"))]
    UnexpectedStatus { status: StatusCode },

    #[snafu(display("missing ssh-version response header"))]
    MissingSshVersion,

    #[snafu(display("invalid ssh-version header value"))]
    InvalidSshVersion { source: http::header::ToStrError },

    #[snafu(display("server offered unsupported version: {server_version}"))]
    VersionMismatch { server_version: String },

    #[snafu(display("failed to register conversation"))]
    Register { source: RegisterError },
}

/// Encode Basic auth header value: `Basic base64(username:password)`.
pub fn encode_basic_auth(username: &str, password: &str) -> HeaderValue {
    let encoded = STANDARD.encode(format!("{username}:{password}"));
    HeaderValue::from_str(&format!("Basic {encoded}"))
        .expect("base64 credentials are valid header value")
}

/// SSH3 client for connecting to a server via Extended CONNECT.
pub struct Ssh3Client {
    authority: String,
    auth_header: HeaderValue,
}

impl Ssh3Client {
    /// Create a client with Basic auth credentials.
    pub fn with_basic_auth(authority: impl Into<String>, username: &str, password: &str) -> Self {
        Self {
            authority: authority.into(),
            auth_header: encode_basic_auth(username, password),
        }
    }

    /// Create a client with a pre-built Authorization header.
    pub fn with_auth_header(authority: impl Into<String>, auth_header: HeaderValue) -> Self {
        Self {
            authority: authority.into(),
            auth_header,
        }
    }

    /// Connect to the SSH3 server via Extended CONNECT.
    ///
    /// Returns a [`Conversation<ConversationHandle>`] on success, which can be
    /// used to open session/forwarding channels and send global requests.
    pub async fn connect<C>(
        &self,
        client: &h3x::client::Client<C>,
    ) -> Result<Conversation<ConversationHandle>, ConnectError>
    where
        C: h3x::quic::Connect + Sync,
        C::Error: Send + Sync,
        C::Connection: h3x::quic::Connection + Send + 'static,
        <C::Connection as h3x::quic::ManageStream>::StreamReader: Send,
        <C::Connection as h3x::quic::ManageStream>::StreamWriter: Send,
    {
        let authority: http::uri::Authority = self
            .authority
            .parse()
            .context(connect_error::InvalidAuthoritySnafu)?;

        let connection =
            client
                .connect(authority.clone())
                .await
                .map_err(|e| ConnectError::QuicConnect {
                    source: Box::new(e),
                })?;

        let uri: http::Uri = format!("https://{authority}{SSH3_CONNECT_PATH}")
            .parse()
            .context(connect_error::InvalidUriSnafu)?;

        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("ssh-version", SSH_VERSION)
            .header(http::header::AUTHORIZATION, self.auth_header.clone())
            .extension(Protocol::new("ssh3"))
            .body(Empty::<bytes::Bytes>::new())
            .context(connect_error::RequestBuildSnafu)?;

        let (mut read_stream, mut write_stream) = connection
            .initial_message_stream()
            .await
            .map_err(|e| ConnectError::ConnectRequest {
                source: Box::new(e),
            })?;

        let conversation_id = write_stream
            .stream_id()
            .await
            .map_err(|e| ConnectError::ConnectRequest {
                source: Box::new(e),
            })?
            .into_inner();

        write_stream
            .send_hyper_request(request)
            .await
            .map_err(|e| ConnectError::ConnectRequest {
                source: Box::new(e),
            })?;

        let mut response = read_stream.read_hyper_response_parts().await.map_err(|e| {
            ConnectError::ConnectRequest {
                source: Box::new(e),
            }
        })?;

        // Skip informational (1xx) responses.
        while response.status.is_informational() {
            response = read_stream.read_hyper_response_parts().await.map_err(|e| {
                ConnectError::ConnectRequest {
                    source: Box::new(e),
                }
            })?;
        }

        if response.status == StatusCode::UNAUTHORIZED {
            return Err(ConnectError::AuthenticationFailed);
        }
        if response.status != StatusCode::OK {
            return Err(ConnectError::UnexpectedStatus {
                status: response.status,
            });
        }

        let server_version = response
            .headers
            .get("ssh-version")
            .ok_or(ConnectError::MissingSshVersion)?
            .to_str()
            .context(connect_error::InvalidSshVersionSnafu)?
            .to_owned();

        if server_version != SSH_VERSION {
            return Err(ConnectError::VersionMismatch { server_version });
        }

        tracing::info!(
            authority = %self.authority,
            conversation_id,
            version = %server_version,
            "SSH3 connection established"
        );

        // Create the SSH3 protocol layer and register this conversation.
        let conn = connection.clone();
        let protocol = Ssh3Protocol::new(move || {
            let conn = conn.clone();
            Box::pin(async move {
                use h3x::codec::BoxReadStream;
                use h3x::codec::BoxWriteStream;
                let (reader, writer) = conn.open_bi().await?;
                Ok((
                    Box::pin(reader) as BoxReadStream,
                    Box::pin(writer) as BoxWriteStream,
                ))
            })
        });
        let session_id = StreamId::try_from(conversation_id).unwrap();
        let handle = protocol
            .register(session_id)
            .context(connect_error::RegisterSnafu)?;

        // Convert HTTP/3 message streams to AsyncRead/AsyncWrite for the
        // control stream (DATA-framed per RFC 9114 §4.4).
        let control_reader = read_stream.into_box_reader();
        let control_writer = write_stream.into_box_writer();

        let conversation = Conversation::new(
            session_id,
            server_version,
            control_reader,
            control_writer,
            handle,
        );

        Ok(conversation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_encoding() {
        let header = encode_basic_auth("user", "password");
        assert_eq!(header.to_str().unwrap(), "Basic dXNlcjpwYXNzd29yZA==");
    }

    #[test]
    fn basic_auth_roundtrip() {
        let header = encode_basic_auth("alice", "s3cret");
        let header_str = header.to_str().unwrap();
        let cred = crate::auth::parse_authorization_header(header_str).unwrap();
        assert_eq!(
            cred,
            crate::auth::AuthCredential::Basic {
                username: "alice".into(),
                password: "s3cret".into(),
            }
        );
    }
}
