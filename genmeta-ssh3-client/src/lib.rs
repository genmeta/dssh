//! SSH3 client implementation.
//!
//! Provides [`Ssh3Client`] for connecting to an SSH3 server over HTTP/3
//! using Extended CONNECT with `:protocol=ssh3`. Currently supports
//! Basic (username/password) authentication only.

pub mod forward;
pub mod session;
pub mod socks5;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use h3x::qpack::field::Protocol;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::Snafu;
/// The SSH3 version string used in the `ssh-version` header.
pub const SSH_VERSION: &str = "michel-ssh3-00";

/// The well-known path for SSH3 Extended CONNECT requests.
pub const SSH3_CONNECT_PATH: &str = "/.well-known/ssh3/connect";

/// Errors that can occur during SSH3 client operations.
#[derive(Debug, Snafu)]
pub enum ClientError {
    /// The Extended CONNECT request could not be sent.
    #[snafu(display("connect failed: {message}"))]
    ConnectFailed { message: String },

    /// The server rejected authentication (HTTP 401).
    #[snafu(display("authentication failed"))]
    AuthenticationFailed,

    /// The server returned an unexpected status code or missing headers.
    #[snafu(display("protocol error: {message}"))]
    ProtocolError { message: String },

    /// The server's ssh-version response did not match any supported version.
    #[snafu(display("version mismatch: server offered {server_version}"))]
    VersionMismatch { server_version: String },
}

/// Configuration for connecting to an SSH3 server.
#[derive(Debug, Clone)]
pub struct Ssh3ClientConfig {
    /// Server authority (host:port).
    pub authority: String,
    /// Username for Basic auth.
    pub username: String,
    /// Password for Basic auth.
    pub password: String,
}

/// An SSH3 client that connects to an SSH3 server via Extended CONNECT.
///
/// Generic over `C: h3x::quic::Connect` — in practice this is usually
/// `Arc<gm_quic::prelude::QuicClient>` wrapped by `H3Client`.
#[derive(Debug, Clone)]
pub struct Ssh3Client {
    config: Ssh3ClientConfig,
}

impl Ssh3Client {
    /// Creates a new SSH3 client with the given configuration.
    pub fn new(config: Ssh3ClientConfig) -> Self {
        Self { config }
    }

    /// Encodes the Basic auth header value: `Basic base64(username:password)`.
    pub fn basic_auth_header(&self) -> HeaderValue {
        let credentials = format!("{}:{}", self.config.username, self.config.password);
        let encoded = STANDARD.encode(credentials.as_bytes());
        HeaderValue::from_str(&format!("Basic {encoded}"))
            .expect("base64-encoded credentials must be valid header value")
    }

    /// Connects to the SSH3 server using the provided h3x `Client`.
    ///
    /// Obtains a connection via `client.connect(authority)`, then sends an
    /// Extended CONNECT request via `connection.execute_hyper_request()` with:
    /// - Method: CONNECT
    /// - `:protocol`: ssh3 (via `Protocol` extension)
    /// - Path: `/.well-known/ssh3/connect`
    /// - `ssh-version`: `michel-ssh3-00`
    /// - `Authorization`: Basic auth from config
    ///
    /// Returns an [`Ssh3Connection`] containing the negotiated version on success.
    pub async fn connect<C>(
        &self,
        client: &h3x::client::Client<C>,
    ) -> Result<Ssh3Connection, ClientError>
    where
        C: h3x::quic::Connect + Sync,
        C::Connection: Send + 'static,
        <C::Connection as h3x::quic::ManageStream>::StreamReader: Send,
        <C::Connection as h3x::quic::ManageStream>::StreamWriter: Send,
    {
        let authority: http::uri::Authority = self
            .config
            .authority
            .parse()
            .map_err(|e| ClientError::ConnectFailed {
                message: format!("invalid authority: {e}"),
            })?;

        let connection = client
            .connect(authority.clone())
            .await
            .map_err(|e| ClientError::ConnectFailed {
                message: format!("{e}"),
            })?;

        let uri: http::Uri =
            format!("https://{authority}{SSH3_CONNECT_PATH}")
                .parse()
                .map_err(|e| ClientError::ConnectFailed {
                    message: format!("invalid URI: {e}"),
                })?;

        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("ssh-version", SSH_VERSION)
            .header(http::header::AUTHORIZATION, self.basic_auth_header())
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .map_err(|e| ClientError::ConnectFailed {
                message: format!("failed to build request: {e}"),
            })?;

        let response = connection
            .execute_hyper_request(request)
            .await
            .map_err(|e| ClientError::ConnectFailed {
                message: format!("{e}"),
            })?;

        // Check response status.
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ClientError::AuthenticationFailed);
        }
        if status != StatusCode::OK {
            return Err(ClientError::ProtocolError {
                message: format!("unexpected status code: {status}"),
            });
        }

        // Validate ssh-version response header.
        let server_version = response
            .headers()
            .get("ssh-version")
            .ok_or_else(|| ClientError::ProtocolError {
                message: "missing ssh-version response header".into(),
            })?
            .to_str()
            .map_err(|_| ClientError::ProtocolError {
                message: "invalid ssh-version response header value".into(),
            })?
            .to_owned();

        if server_version != SSH_VERSION {
            return Err(ClientError::VersionMismatch { server_version });
        }

        tracing::info!(
            authority = %self.config.authority,
            version = %server_version,
            "SSH3 connection established"
        );

        Ok(Ssh3Connection { server_version })
    }
}

/// An established SSH3 conversation over an Extended CONNECT stream.
///
/// Contains the negotiated SSH version from a successful handshake.
pub struct Ssh3Connection {
    /// The negotiated SSH3 version string.
    server_version: String,
}

impl Ssh3Connection {
    /// Returns the negotiated SSH version string.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }
}

/// Encode a username and password into a Basic auth `Authorization` header value.
///
/// Returns the full header value string: `Basic base64(username:password)`.
pub fn encode_basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{username}:{password}");
    let encoded = STANDARD.encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

/// Build the request headers for an SSH3 Extended CONNECT, without sending.
///
/// Useful for unit testing request construction without a QUIC stack.
pub fn build_connect_headers(
    authority: &str,
    username: &str,
    password: &str,
) -> (http::Uri, http::HeaderMap) {
    let uri: http::Uri = format!("https://{authority}{SSH3_CONNECT_PATH}")
        .parse()
        .expect("authority must produce a valid URI");

    let mut headers = http::HeaderMap::new();
    headers.insert(
        "ssh-version",
        HeaderValue::from_static(SSH_VERSION),
    );
    let auth_value = encode_basic_auth(username, password);
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_str(&auth_value).expect("auth value must be valid header"),
    );

    (uri, headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // 1. Basic auth header encoding
    // -----------------------------------------------------------------------

    #[test]
    fn basic_auth_header_encoding() {
        // "user:password" → base64 "dXNlcjpwYXNzd29yZA=="
        let auth = encode_basic_auth("user", "password");
        assert_eq!(auth, "Basic dXNlcjpwYXNzd29yZA==");

        // Verify round-trip via proto parser.
        let cred =
            genmeta_ssh3_proto::auth::parse_authorization_header(&auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh3_proto::auth::AuthCredential::Basic {
                username: "user".into(),
                password: "password".into(),
            }
        );
    }

    #[test]
    fn basic_auth_header_encoding_with_special_chars() {
        // Password with colons: "admin:p:a:ss"
        let auth = encode_basic_auth("admin", "p:a:ss");
        let cred =
            genmeta_ssh3_proto::auth::parse_authorization_header(&auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh3_proto::auth::AuthCredential::Basic {
                username: "admin".into(),
                password: "p:a:ss".into(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // 2. Connect request construction
    // -----------------------------------------------------------------------

    #[test]
    fn connect_request_construction() {
        let (uri, headers) = build_connect_headers("localhost:4433", "user", "pass");

        // Verify URI.
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(uri.authority().unwrap().as_str(), "localhost:4433");
        assert_eq!(uri.path(), SSH3_CONNECT_PATH);

        // Verify ssh-version header.
        let version = headers.get("ssh-version").unwrap().to_str().unwrap();
        assert_eq!(version, SSH_VERSION);

        // Verify Authorization header.
        let auth = headers
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(auth.starts_with("Basic "));

        // Verify it decodes correctly.
        let cred =
            genmeta_ssh3_proto::auth::parse_authorization_header(auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh3_proto::auth::AuthCredential::Basic {
                username: "user".into(),
                password: "pass".into(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // 3. Version negotiation header
    // -----------------------------------------------------------------------

    #[test]
    fn version_negotiation_header() {
        assert_eq!(SSH_VERSION, "michel-ssh3-00");

        let (_, headers) = build_connect_headers("example.com:443", "u", "p");
        let version = headers.get("ssh-version").unwrap().to_str().unwrap();
        assert_eq!(version, "michel-ssh3-00");
    }

    // -----------------------------------------------------------------------
    // 4. SSH3 well-known path
    // -----------------------------------------------------------------------

    #[test]
    fn ssh3_well_known_path() {
        assert_eq!(SSH3_CONNECT_PATH, "/.well-known/ssh3/connect");
    }

    // -----------------------------------------------------------------------
    // 5. Client error display
    // -----------------------------------------------------------------------

    #[test]
    fn client_error_display() {
        let err = ClientError::AuthenticationFailed;
        assert_eq!(err.to_string(), "authentication failed");

        let err = ClientError::ConnectFailed {
            message: "timeout".into(),
        };
        assert!(err.to_string().contains("connect failed"));
        assert!(err.to_string().contains("timeout"));

        let err = ClientError::ProtocolError {
            message: "bad status".into(),
        };
        assert!(err.to_string().contains("protocol error"));

        let err = ClientError::VersionMismatch {
            server_version: "unknown-99".into(),
        };
        assert!(err.to_string().contains("version mismatch"));
        assert!(err.to_string().contains("unknown-99"));
    }

    // -----------------------------------------------------------------------
    // 6. Ssh3Client basic_auth_header method
    // -----------------------------------------------------------------------

    #[test]
    fn ssh3_client_basic_auth_header_method() {
        let client = Ssh3Client::new(Ssh3ClientConfig {
            authority: "localhost:443".into(),
            username: "test".into(),
            password: "testpass".into(),
        });

        let header = client.basic_auth_header();
        let header_str = header.to_str().unwrap();

        // "test:testpass" → base64 "dGVzdDp0ZXN0cGFzcw=="
        assert_eq!(header_str, "Basic dGVzdDp0ZXN0cGFzcw==");

        // Verify it round-trips through the proto parser.
        let cred =
            genmeta_ssh3_proto::auth::parse_authorization_header(header_str).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh3_proto::auth::AuthCredential::Basic {
                username: "test".into(),
                password: "testpass".into(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // 7. Ssh3ClientConfig construction
    // -----------------------------------------------------------------------

    #[test]
    fn ssh3_client_config_construction() {
        let config = Ssh3ClientConfig {
            authority: "example.com:22".into(),
            username: "alice".into(),
            password: "secret".into(),
        };

        let client = Ssh3Client::new(config.clone());
        assert_eq!(client.config.authority, "example.com:22");
        assert_eq!(client.config.username, "alice");
        assert_eq!(client.config.password, "secret");
    }

    // -----------------------------------------------------------------------
    // 8. Empty password encoding
    // -----------------------------------------------------------------------

    #[test]
    fn basic_auth_empty_password() {
        let auth = encode_basic_auth("user", "");
        // "user:" → base64 "dXNlcjo="
        let cred =
            genmeta_ssh3_proto::auth::parse_authorization_header(&auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh3_proto::auth::AuthCredential::Basic {
                username: "user".into(),
                password: "".into(),
            }
        );
    }
}
