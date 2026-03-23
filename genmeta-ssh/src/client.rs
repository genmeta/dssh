//! SSH3 client: connect to an SSH3 server via Extended CONNECT.
//!
//! Provides [`Ssh3Client`] for establishing an SSH3 connection over HTTP/3,
//! and [`Ssh3Connection`] for opening channels on the established connection.

use std::sync::Arc;

use base64::engine::{Engine, general_purpose::STANDARD};
use h3x::codec::{EncodeInto, SinkWriter, StreamReader};
use h3x::message::stream::{ReadStream, WriteStream};
use h3x::qpack::field::Protocol;
use h3x::quic::GetStreamIdExt;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::{ResultExt, Snafu};

use crate::constants::SSH_VERSION;

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
    ) -> Result<
        Ssh3Connection<Arc<h3x::connection::Connection<C::Connection>>>,
        ConnectError,
    >
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

        Ok(Ssh3Connection {
            server_version,
            conversation_id,
            _control_reader: read_stream,
            _control_writer: write_stream,
            connection,
        })
    }
}

/// An established SSH3 connection.
///
/// Holds the control stream and the underlying h3x connection handle.
/// Use [`open_session`](Ssh3Connection::open_session) to create session
/// channels.
pub struct Ssh3Connection<C> {
    server_version: String,
    conversation_id: u64,
    _control_reader: ReadStream,
    _control_writer: WriteStream,
    connection: C,
}

impl<C> Ssh3Connection<C> {
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn conversation_id(&self) -> u64 {
        self.conversation_id
    }

    pub fn connection(&self) -> &C {
        &self.connection
    }
}

/// Methods available when `C` is a full h3x connection that can open streams.
impl<C> Ssh3Connection<Arc<h3x::connection::Connection<C>>>
where
    C: h3x::quic::Connection + Sync + 'static,
    C::StreamReader: Send,
    C::StreamWriter: Send,
{
    /// Open a session channel and return a [`ClientSession`](crate::session::client::ClientSession).
    pub async fn open_session(
        &self,
    ) -> Result<
        crate::session::client::ClientSession<
            StreamReader<C::StreamReader>,
            SinkWriter<C::StreamWriter>,
        >,
        OpenChannelError,
    > {
        let (reader, writer) = self.open_channel(&crate::forward::SessionChannelOpen).await?;

        Ok(crate::session::client::ClientSession::new(
            crate::conversation::SshChannelReader::new(reader),
            crate::conversation::SshChannelWriter::new(writer),
        ))
    }

    /// Open a channel: write the full header (signal value + session ID +
    /// max_message_size + channel_type + payload), read the confirmation
    /// response, and return the raw stream pair.
    async fn open_channel<CO, PE>(
        &self,
        channel: &CO,
    ) -> Result<(StreamReader<C::StreamReader>, SinkWriter<C::StreamWriter>), OpenChannelError>
    where
        CO: crate::conversation::ChannelOpen,
        PE: std::error::Error + Send + Sync + 'static,
        for<'w> CO::Payload:
            h3x::codec::EncodeInto<&'w mut SinkWriter<C::StreamWriter>, Output = (), Error = PE>,
    {
        use crate::constants::{CHANNEL_SIGNAL_VALUE, DEFAULT_MAX_MESSAGE_SIZE};
        use h3x::codec::EncodeExt;

        let (reader, writer) = self.open_bi().await?;
        let mut reader = StreamReader::new(reader);
        let mut writer = SinkWriter::new(writer);

        // Write full channel open header (signal value + session ID + SSH fields).
        let session_id =
            h3x::stream_id::StreamId(h3x::varint::VarInt::try_from(self.conversation_id).unwrap());
        writer
            .encode_one(CHANNEL_SIGNAL_VALUE)
            .await
            .map_err(|e| OpenChannelError::ChannelOpen {
                source: Box::new(e),
            })?;
        writer
            .encode_one(session_id)
            .await
            .map_err(|e| OpenChannelError::ChannelOpen {
                source: Box::new(e),
            })?;
        writer
            .encode_one(DEFAULT_MAX_MESSAGE_SIZE)
            .await
            .map_err(|e| OpenChannelError::ChannelOpen {
                source: Box::new(e),
            })?;
        writer
            .encode_one(channel.channel_type())
            .await
            .map_err(|e| OpenChannelError::ChannelOpen {
                source: Box::new(std::io::Error::other(e)),
            })?;
        channel
            .payload()
            .clone()
            .encode_into(&mut writer)
            .await
            .map_err(|e| OpenChannelError::ChannelOpen {
                source: Box::new(e),
            })?;
        tokio::io::AsyncWriteExt::flush(&mut writer)
            .await
            .map_err(|e| OpenChannelError::ChannelOpen {
                source: Box::new(e),
            })?;

        // Read confirmation.
        crate::conversation::read_channel_open_response(&mut reader)
            .await
            .map_err(|e| OpenChannelError::ChannelOpenResponse {
                source: Box::new(e),
            })?;

        Ok((reader, writer))
    }

    async fn open_bi(&self) -> Result<(C::StreamReader, C::StreamWriter), OpenChannelError> {
        self.connection
            .open_bi()
            .await
            .map_err(|e| OpenChannelError::OpenStream {
                source: Box::new(e),
            })
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum OpenChannelError {
    #[snafu(display("failed to open QUIC stream"))]
    OpenStream {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to send channel open"))]
    ChannelOpen {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to read channel open response"))]
    ChannelOpenResponse {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
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
