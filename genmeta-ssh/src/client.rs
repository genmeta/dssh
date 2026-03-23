//! SSH3 client: connect to an SSH3 server via Extended CONNECT.
//!
//! Provides [`Ssh3Client`] for establishing an SSH3 connection over HTTP/3,
//! and [`Ssh3Connection`] for opening channels on the established connection.

use base64::engine::{Engine, general_purpose::STANDARD};
use h3x::qpack::field::Protocol;
use h3x::quic::GetStreamIdExt;
use h3x::stream_id::StreamId;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::{ResultExt, Snafu};

use crate::constants::{DEFAULT_MAX_MESSAGE_SIZE, SSH_VERSION};
use crate::conversation::{
    Conversation, OpenChannelError, SshChannelReader, SshChannelWriter,
};
use crate::forward::SessionChannelOpen;
use crate::protocol::{
    ConversationHandle, HandleError, RegisterError, Ssh3Protocol,
    Ssh3StreamReader, Ssh3StreamWriter,
};

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
    /// Returns an [`Ssh3Connection`] on success, which can be used to
    /// open session and forwarding channels.
    pub async fn connect<C>(
        &self,
        client: &h3x::client::Client<C>,
    ) -> Result<Ssh3Connection, ConnectError>
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

        let connection = client.connect(authority.clone()).await.map_err(|e| {
            ConnectError::QuicConnect {
                source: Box::new(e),
            }
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

        let conversation = Conversation::new(session_id, control_reader, control_writer, handle);

        Ok(Ssh3Connection {
            server_version,
            conversation,
        })
    }
}

/// An established SSH3 connection.
///
/// Wraps a [`Conversation<ConversationHandle>`] that manages the control
/// stream (global requests/notifications) and channel lifecycle.
///
/// Use [`open_session`](Ssh3Connection::open_session) to create session
/// channels, or [`conversation`](Ssh3Connection::conversation) for direct
/// access to the underlying conversation.
pub struct Ssh3Connection {
    server_version: String,
    conversation: Conversation<ConversationHandle>,
}

impl Ssh3Connection {
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn conversation_id(&self) -> u64 {
        self.conversation.id().into_inner()
    }

    /// Returns a reference to the underlying [`Conversation`].
    ///
    /// Use this for reverse forwarding, global requests, or any other
    /// operation that requires direct conversation access.
    pub fn conversation(&self) -> &Conversation<ConversationHandle> {
        &self.conversation
    }

    /// Open a session channel and return a [`ClientSession`](crate::session::client::ClientSession).
    pub async fn open_session(
        &self,
    ) -> Result<
        crate::session::client::ClientSession<Ssh3StreamReader, Ssh3StreamWriter>,
        OpenChannelError<HandleError, std::convert::Infallible>,
    > {
        let (reader, writer) = self
            .conversation
            .open_channel(&SessionChannelOpen, DEFAULT_MAX_MESSAGE_SIZE)
            .await?;

        Ok(crate::session::client::ClientSession::new(
            SshChannelReader::new(reader),
            SshChannelWriter::new(writer),
        ))
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
