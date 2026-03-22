//! SSH3 client implementation.
//!
//! Provides [`Ssh3Client`] for connecting to an SSH3 server over HTTP/3
//! using Extended CONNECT with `:protocol=ssh3`. Currently supports
//! Basic (username/password) authentication only.

pub mod forward;
pub mod session;
pub mod socks5;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
pub use genmeta_ssh::SSH_VERSION;
use h3x::codec::{SinkWriter, StreamReader};
use h3x::gm_quic::H3Client;
use h3x::message::stream::{ReadStream, WriteStream};
use h3x::qpack::field::Protocol;
use h3x::quic::GetStreamIdExt;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::{ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWriteExt};

/// The well-known path for SSH3 Extended CONNECT requests.
pub const SSH3_CONNECT_PATH: &str = "/.well-known/ssh3/connect";

pub fn init_client_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();
}

pub async fn run_env_client() -> Result<(), Box<dyn std::error::Error>> {
    let authority = std::env::var("SSH3_AUTHORITY")?;
    let username = std::env::var("SSH3_USERNAME")?;
    let password = std::env::var("SSH3_PASSWORD")?;

    let client = H3Client::builder()
        .without_server_cert_verification()
        .without_identity()?
        .build();
    let ssh3 = Ssh3Client::new(Ssh3ClientConfig {
        authority,
        username,
        password,
    });

    let connection = ssh3.connect(&client).await?;
    if let Ok(command) = std::env::var("SSH3_EXEC") {
        let mut channel = connection
            .open_exec_channel(command.as_bytes())
            .await?;
        channel.send_eof().await?;
        let exit = print_session_events(channel.reader()).await?;
        if let Some(code) = exit {
            std::process::exit(code as i32);
        }
        return Ok(());
    }

    if env_flag("SSH3_SHELL") {
        run_env_shell(connection).await?;
        return Ok(());
    }

    println!("{}", connection.server_version());
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

async fn run_env_shell(
    connection: Ssh3Connection<
        std::sync::Arc<h3x::connection::Connection<h3x::gm_quic::prelude::Connection>>,
    >,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut channel = connection.open_session_channel().await?;
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    let width_cols = std::env::var("SSH3_TERM_COLS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(80);
    let height_rows = std::env::var("SSH3_TERM_ROWS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(24);

    channel
        .send_pty_request(&term, width_cols, height_rows, 0, 0, &[])
        .await?;
    channel.send_shell_request().await?;

    let (mut reader, mut writer) = channel.into_parts();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 8192];
        loop {
            let read = stdin.read(&mut buf).await?;
            if read == 0 {
                genmeta_ssh::write_channel_eof(&mut writer)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                return Ok::<(), io::Error>(());
            }
            genmeta_ssh::write_channel_data(
                &mut writer,
                genmeta_ssh::codec::SshBytes::from(buf[..read].to_vec()),
            )
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        }
    });

    let exit = print_session_events(&mut reader).await?;
    stdin_task.abort();
    let _ = stdin_task.await;

    if let Some(code) = exit {
        std::process::exit(code as i32);
    }
    Ok(())
}

async fn print_session_events<R>(reader: &mut R) -> Result<Option<u32>, Box<dyn std::error::Error>>
where
    R: AsyncRead + Send + Unpin,
{
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit_status = None;

    while let Some(event) = session::read_session_event(reader).await? {
        match event {
            session::SessionEvent::Stdout(data) => stdout.write_all(&data).await?,
            session::SessionEvent::Stderr(data) => stderr.write_all(&data).await?,
            session::SessionEvent::ExitStatus(code) => exit_status = Some(code),
            session::SessionEvent::ExitSignal { .. } => exit_status = Some(255),
            session::SessionEvent::Close => break,
            session::SessionEvent::Eof
            | session::SessionEvent::Success
            | session::SessionEvent::Failure => {}
        }
    }

    stdout.flush().await?;
    stderr.flush().await?;
    Ok(exit_status)
}

/// Errors that can occur during SSH3 client operations.
#[derive(Debug, Snafu)]
pub enum ClientError {
    /// The authority string could not be parsed.
    #[snafu(display("invalid authority"))]
    InvalidAuthority { source: http::uri::InvalidUri },

    /// QUIC-level connection establishment failed.
    #[snafu(display("failed to establish QUIC connection"))]
    QuicConnectFailed {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The constructed URI is invalid.
    #[snafu(display("invalid URI"))]
    InvalidUri { source: http::uri::InvalidUri },

    /// Building the HTTP request failed.
    #[snafu(display("failed to build request"))]
    RequestBuildFailed { source: http::Error },

    /// The Extended CONNECT request could not be sent.
    #[snafu(display("extended CONNECT request failed"))]
    ConnectRequestFailed {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The server rejected authentication (HTTP 401).
    #[snafu(display("authentication failed"))]
    AuthenticationFailed,

    /// The server returned an unexpected status code.
    #[snafu(display("unexpected status code: {status}"))]
    UnexpectedStatus { status: StatusCode },

    /// The response is missing the `ssh-version` header.
    #[snafu(display("missing ssh-version response header"))]
    MissingSshVersionHeader,

    /// The `ssh-version` response header value is not valid ASCII.
    #[snafu(display("invalid ssh-version response header value"))]
    InvalidSshVersionHeader { source: http::header::ToStrError },

    /// The server's ssh-version response did not match any supported version.
    #[snafu(display("server offered unsupported version {server_version}"))]
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
        let encoded = base64::Engine::encode(&STANDARD, credentials.as_bytes());
        HeaderValue::from_str(&format!("Basic {encoded}"))
            .expect("base64-encoded credentials must be valid header value")
    }

    /// Connects to the SSH3 server using the provided h3x `Client`.
    ///
    /// Obtains a connection via `client.connect(authority)`, then sends an
    /// Extended CONNECT request with:
    /// - Method: CONNECT
    /// - `:protocol`: ssh3 (via `Protocol` extension)
    /// - Path: `/.well-known/ssh3/connect`
    /// - `ssh-version`: `genmeta-ssh3-00`
    /// - `Authorization`: Basic auth from config
    ///
    /// Returns an [`Ssh3Connection`] containing the negotiated version and
    /// the underlying h3x connection handle on success.
    pub async fn connect<C>(
        &self,
        client: &h3x::client::Client<C>,
    ) -> Result<
        Ssh3Connection<std::sync::Arc<h3x::connection::Connection<C::Connection>>>,
        ClientError,
    >
    where
        C: h3x::quic::Connect + Sync,
        C::Error: Send + Sync,
        C::Connection: h3x::quic::Connection + Send + 'static,
        <C::Connection as h3x::quic::ManageStream>::StreamReader: Send,
        <C::Connection as h3x::quic::ManageStream>::StreamWriter: Send,
    {
        let authority: http::uri::Authority = self
            .config
            .authority
            .parse()
            .context(InvalidAuthoritySnafu)?;

        let connection = client.connect(authority.clone()).await.map_err(|e| {
            ClientError::QuicConnectFailed {
                source: Box::new(e),
            }
        })?;

        let uri: http::Uri = format!("https://{authority}{SSH3_CONNECT_PATH}")
            .parse()
            .context(InvalidUriSnafu)?;

        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("ssh-version", SSH_VERSION)
            .header(http::header::AUTHORIZATION, self.basic_auth_header())
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .context(RequestBuildFailedSnafu)?;

        let (mut read_stream, mut write_stream) = connection
            .initial_message_stream()
            .await
            .map_err(|e| ClientError::ConnectRequestFailed {
                source: Box::new(e),
            })?;

        let conversation_id = write_stream
            .stream_id()
            .await
            .map_err(|e| ClientError::ConnectRequestFailed {
                source: Box::new(e),
            })?
            .into_inner();

        write_stream
            .send_hyper_request(request)
            .await
            .map_err(|e| ClientError::ConnectRequestFailed {
                source: Box::new(e),
            })?;

        let mut response = read_stream.read_hyper_response_parts().await.map_err(|e| {
            ClientError::ConnectRequestFailed {
                source: Box::new(e),
            }
        })?;
        while response.status.is_informational() {
            response = read_stream.read_hyper_response_parts().await.map_err(|e| {
                ClientError::ConnectRequestFailed {
                    source: Box::new(e),
                }
            })?;
        }

        let status = response.status;
        if status == StatusCode::UNAUTHORIZED {
            return Err(ClientError::AuthenticationFailed);
        }
        if status != StatusCode::OK {
            return Err(ClientError::UnexpectedStatus { status });
        }

        let server_version = response
            .headers
            .get("ssh-version")
            .ok_or(ClientError::MissingSshVersionHeader)?
            .to_str()
            .context(InvalidSshVersionHeaderSnafu)?
            .to_owned();

        if server_version != SSH_VERSION {
            return Err(ClientError::VersionMismatch { server_version });
        }

        tracing::info!(
            authority = %self.config.authority,
            conversation_id,
            version = %server_version,
            "SSH3 connection established"
        );

        Ok(Ssh3Connection {
            server_version,
            conversation_id,
            _control_stream: ControlStream {
                _reader: read_stream,
                _writer: write_stream,
            },
            connection,
        })
    }
}

/// An established SSH3 conversation over an Extended CONNECT stream.
///
/// Contains the negotiated SSH version and the underlying h3x connection
/// handle from a successful handshake.
pub struct Ssh3Connection<C> {
    /// The negotiated SSH3 version string.
    server_version: String,
    conversation_id: u64,
    _control_stream: ControlStream,
    /// The h3x connection handle for opening channels.
    connection: C,
}

struct ControlStream {
    _reader: ReadStream,
    _writer: WriteStream,
}

impl<C> Ssh3Connection<C> {
    /// Returns the negotiated SSH version string.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn conversation_id(&self) -> u64 {
        self.conversation_id
    }

    /// Returns a reference to the underlying h3x connection handle.
    pub fn connection(&self) -> &C {
        &self.connection
    }
}

impl<C> Ssh3Connection<std::sync::Arc<h3x::connection::Connection<C>>>
where
    C: h3x::quic::Connection + Sync + 'static,
    C::StreamReader: Send,
    C::StreamWriter: Send,
{
    pub async fn open_session_channel(
        &self,
    ) -> Result<
        session::SessionChannel<StreamReader<C::StreamReader>, SinkWriter<C::StreamWriter>>,
        session::ClientSessionError,
    > {
        let (reader, writer) =
            self.connection
                .open_bi()
                .await
                .map_err(|source| session::ClientSessionError::OpenStream {
                    source: io::Error::other(source),
                })?;
        session::open_session_channel(
            StreamReader::new(reader),
            SinkWriter::new(writer),
            self.conversation_id,
        )
        .await
    }

    pub async fn open_exec_channel(
        &self,
        command: &[u8],
    ) -> Result<
        session::SessionChannel<StreamReader<C::StreamReader>, SinkWriter<C::StreamWriter>>,
        session::ClientSessionError,
    > {
        let mut channel = self.open_session_channel().await?;
        channel.send_exec_request(command).await?;
        Ok(channel)
    }

    pub async fn open_shell_channel(
        &self,
    ) -> Result<
        session::SessionChannel<StreamReader<C::StreamReader>, SinkWriter<C::StreamWriter>>,
        session::ClientSessionError,
    > {
        let mut channel = self.open_session_channel().await?;
        channel.send_shell_request().await?;
        Ok(channel)
    }
}

/// Encode a username and password into a Basic auth `Authorization` header value.
///
/// Returns the full header value string: `Basic base64(username:password)`.
pub fn encode_basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{username}:{password}");
    let encoded = base64::Engine::encode(&STANDARD, credentials.as_bytes());
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
    headers.insert("ssh-version", HeaderValue::from_static(SSH_VERSION));
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
        let cred = genmeta_ssh::parse_authorization_header(&auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh::auth::AuthCredential::Basic {
                username: "user".into(),
                password: "password".into(),
            }
        );
    }

    #[test]
    fn basic_auth_header_encoding_with_special_chars() {
        // Password with colons: "admin:p:a:ss"
        let auth = encode_basic_auth("admin", "p:a:ss");
        let cred = genmeta_ssh::parse_authorization_header(&auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh::auth::AuthCredential::Basic {
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
        let cred = genmeta_ssh::parse_authorization_header(auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh::auth::AuthCredential::Basic {
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
        assert_eq!(SSH_VERSION, "genmeta-ssh3-00");

        let (_, headers) = build_connect_headers("example.com:443", "u", "p");
        let version = headers.get("ssh-version").unwrap().to_str().unwrap();
        assert_eq!(version, SSH_VERSION);
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

        let err = ClientError::QuicConnectFailed {
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "test",
            )),
        };
        assert_eq!(err.to_string(), "failed to establish QUIC connection");

        let err = ClientError::UnexpectedStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
        };
        assert!(err.to_string().contains("unexpected status code"));
        assert!(err.to_string().contains("500"));

        let err = ClientError::MissingSshVersionHeader;
        assert_eq!(err.to_string(), "missing ssh-version response header");

        let err = ClientError::VersionMismatch {
            server_version: "unknown-99".into(),
        };
        assert!(err.to_string().contains("unsupported version"));
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
        let cred = genmeta_ssh::parse_authorization_header(header_str).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh::auth::AuthCredential::Basic {
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
        let cred = genmeta_ssh::parse_authorization_header(&auth).unwrap();
        assert_eq!(
            cred,
            genmeta_ssh::auth::AuthCredential::Basic {
                username: "user".into(),
                password: "".into(),
            }
        );
    }
}
