//! DShell session types, PTY, signal handling, and process management.
//!
//! This module provides:
//! - Session channel request/notice types (exec, shell, PTY, signal, window-change)
//! - [`ClientSession`](client::ClientSession) for client-side session channel management
//! - [`run_piped`](process::run_piped) / [`run_pty`](process::run_pty) for server-side
//!   command execution with I/O relay
//! - [`PtyPair`](pty::PtyPair) for PTY allocation
//! - [`Signal`](signal::Signal) for SSH signal handling
//! - Bootstrap types for privilege-separated child processes

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod dispatcher;
#[cfg(feature = "pam")]
pub mod pam;
#[cfg(feature = "server")]
pub mod privilege;
#[cfg(feature = "server")]
pub mod process;
#[cfg(feature = "server")]
pub mod pty;
#[cfg(feature = "server")]
pub mod signal;

use std::pin::pin;

use crate::{
    codec::{CodecError, SshBool, SshBytes, SshString},
    conversation::{EmptyPayload, NotifyChannelRequest, WantReplyChannelRequest},
};
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::varint::VarInt;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite};

// =========================================================================
// Server-only types: user identity, authentication, session bootstrap
// =========================================================================

#[cfg(feature = "server")]
mod server {
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};
    use snafu::{OptionExt, ResultExt, Snafu};

    /// User identity from `/etc/passwd`.
    #[derive(Debug, Clone)]
    pub struct UserInfo {
        /// Login name.
        pub username: String,
        /// POSIX user ID.
        pub uid: u32,
        /// POSIX group ID.
        pub gid: u32,
        /// User's home directory.
        pub home: PathBuf,
        /// User's login shell.
        pub shell: PathBuf,
        /// Environment variables from PAM modules (populated by `open_session`).
        pub pam_env: Vec<(String, String)>,
    }

    /// Error from [`lookup_user`].
    #[derive(Debug, Snafu)]
    #[snafu(module)]
    pub enum LookupUserError {
        /// Failed to query `/etc/passwd` for the user.
        #[snafu(display("failed to query user from /etc/passwd"))]
        UserQuery { source: nix::Error },

        /// The username does not exist in `/etc/passwd`.
        #[snafu(display("user not found in /etc/passwd: {username}"))]
        UserNotFound { username: String },
    }

    /// Look up a user in `/etc/passwd` by name.
    ///
    /// This does **not** perform any authentication; it only reads the
    /// system user database.  Used as a fallback when PAM is unavailable
    /// and the client has already been authenticated at the transport
    /// layer (mTLS).
    pub async fn lookup_user(username: &str) -> Result<UserInfo, LookupUserError> {
        let username = username.to_owned();
        tokio::task::spawn_blocking(move || {
            let user = nix::unistd::User::from_name(&username)
                .context(lookup_user_error::UserQuerySnafu)?
                .context(lookup_user_error::UserNotFoundSnafu { username })?;
            Ok(UserInfo {
                username: user.name,
                uid: user.uid.as_raw(),
                gid: user.gid.as_raw(),
                home: user.dir,
                shell: user.shell,
                pam_env: Vec::new(),
            })
        })
        .await
        .expect("lookup_user blocking task cancelled")
    }

    /// Check whether login is prohibited by `/etc/nologin` or `/var/run/nologin`.
    ///
    /// Root (uid 0) is always allowed. For non-root users, if either nologin
    /// file exists, login is denied. When PAM is in use, `pam_nologin.so`
    /// handles this check during `acct_mgmt`; this function is the fallback
    /// for non-PAM builds.
    pub fn check_nologin(uid: u32) -> Result<(), String> {
        if uid == 0 {
            return Ok(());
        }
        for path in &["/etc/nologin", "/var/run/nologin"] {
            if std::path::Path::new(path).exists() {
                let msg = std::fs::read_to_string(path).unwrap_or_default();
                return Err(if msg.is_empty() {
                    "system is unavailable".to_owned()
                } else {
                    msg
                });
            }
        }
        Ok(())
    }

    /// Argument to the outer [`AuthenticateFn`]: carries the credential to the child
    /// process for PAM authentication.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthRequest {
        /// Username extracted from the HTTP Authorization header.
        pub username: String,
        /// Authentication credential for PAM.
        pub credential: crate::auth::AuthCredential,
    }

    /// Authentication success payload.
    #[derive(Serialize, Deserialize)]
    pub struct AuthenticatedSession {
        /// Inner remote function that starts the session.
        pub start_session: StartSessionFn,
    }

    /// Argument to the inner [`StartSessionFn`]: everything the child needs to
    /// construct a [`Conversation`](crate::conversation::Conversation) after
    /// authentication succeeds and the parent completes the HTTP upgrade.
    ///
    /// Stream data travels through Unix socketpairs via h3x WebTransport IPC,
    /// not through remoc serialization.
    #[derive(Serialize, Deserialize)]
    pub struct SessionBootstrap {
        /// WebTransport session IPC bootstrap.
        pub webtransport_session: h3x::ipc::webtransport::WebTransportSessionBootstrap,
        /// Negotiated SSH version string.
        pub peer_version: String,
    }

    /// Error returned by the outer [`AuthenticateFn`] when PAM authentication or
    /// user lookup fails.
    #[derive(Debug, Snafu, Serialize, Deserialize)]
    #[snafu(module)]
    pub enum AuthError {
        /// PAM authentication or account management failed.
        #[snafu(display("PAM authentication failed: {reason}"))]
        PamFailed {
            /// Human-readable reason from PAM.
            reason: String,
        },

        /// The authenticated user does not exist in `/etc/passwd`.
        #[snafu(display("user not found: {username}"))]
        UserNotFound {
            /// The username that was looked up.
            username: String,
        },

        /// The remote function call itself failed (transport error).
        #[snafu(display("remote call failed"))]
        RemoteCall {
            /// The underlying call error.
            source: remoc::rfn::CallError,
        },
    }

    impl From<remoc::rfn::CallError> for AuthError {
        fn from(source: remoc::rfn::CallError) -> Self {
            Self::RemoteCall { source }
        }
    }

    /// Error returned by the inner [`StartSessionFn`] when the session fails to
    /// start (privilege drop failure, etc.).
    #[derive(Debug, Snafu, Serialize, Deserialize)]
    #[snafu(module)]
    pub enum SessionRunError {
        /// Dropping privileges to the target user failed.
        #[snafu(display("failed to drop privileges: {reason}"))]
        DropPrivileges {
            /// Human-readable reason for the failure.
            reason: String,
        },

        /// Building the [`Conversation`](crate::conversation::Conversation) failed.
        #[snafu(display("failed to build conversation: {reason}"))]
        ConversationBuild {
            /// Human-readable reason for the failure.
            reason: String,
        },

        /// Running the session dispatcher failed.
        #[snafu(display("session dispatcher failed: {reason}"))]
        Session {
            /// Human-readable reason for the failure.
            reason: String,
        },

        /// The remote function call itself failed (transport error).
        #[snafu(display("remote call failed"))]
        RemoteCall {
            /// The underlying call error.
            source: remoc::rfn::CallError,
        },
    }

    impl From<remoc::rfn::CallError> for SessionRunError {
        fn from(source: remoc::rfn::CallError) -> Self {
            Self::RemoteCall { source }
        }
    }

    /// Outer remote function: the child creates this and sends it to the parent.
    ///
    /// When the parent calls it with [`AuthRequest`], the child performs PAM
    /// authentication. On success it returns an [`AuthenticatedSession`]
    /// continuation; on failure it returns [`AuthError`].
    pub type AuthenticateFn =
        remoc::rfn::RFnOnce<(AuthRequest,), Result<AuthenticatedSession, AuthError>>;

    /// Inner remote function: returned by [`AuthenticateFn`] on success.
    ///
    /// When the parent calls it with [`SessionBootstrap`] (after HTTP upgrade),
    /// the child drops privileges and runs the session dispatcher.
    pub type StartSessionFn = remoc::rfn::RFnOnce<(SessionBootstrap,), Result<(), SessionRunError>>;
}

#[cfg(feature = "server")]
pub use server::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum SessionCodecError {
    #[snafu(display("session codec failed"))]
    Codec { source: CodecError },

    #[snafu(display("session stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("session stream write failed"))]
    WriteIo { source: std::io::Error },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: SshBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemRequest {
    pub subsystem_name: SshString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitStatusRequest {
    pub exit_status: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignalRequest {
    pub signal_name: SshString,
    pub core_dumped: SshBool,
    pub error_message: SshString,
    pub language_tag: SshString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    pub term_type: SshString,
    pub width_cols: VarInt,
    pub height_rows: VarInt,
    pub width_px: VarInt,
    pub height_px: VarInt,
    pub terminal_modes: SshBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowChangeRequest {
    pub width_cols: VarInt,
    pub height_rows: VarInt,
    pub width_px: VarInt,
    pub height_px: VarInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalRequest {
    pub signal_name: SshString,
}

/// Client-requested environment variable (RFC 4254 §6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvRequest {
    pub name: SshString,
    pub value: SshString,
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExecRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            command: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ExecRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.command)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SubsystemRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            subsystem_name: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for SubsystemRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.subsystem_name)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitStatusRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let exit_status: VarInt = stream
            .decode_one()
            .await
            .context(session_codec_error::ReadIoSnafu)?;
        Ok(Self { exit_status })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ExitStatusRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.exit_status)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ExitSignalRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let signal_name: SshString = stream
            .decode_one()
            .await
            .context(session_codec_error::CodecSnafu)?;
        let core_dumped: SshBool = stream
            .decode_one()
            .await
            .context(session_codec_error::CodecSnafu)?;
        let error_message: SshString = stream
            .decode_one()
            .await
            .context(session_codec_error::CodecSnafu)?;
        let language_tag: SshString = stream
            .decode_one()
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(Self {
            signal_name,
            core_dumped,
            error_message,
            language_tag,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for ExitSignalRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.signal_name)
            .await
            .context(session_codec_error::CodecSnafu)?;
        stream
            .encode_one(self.core_dumped)
            .await
            .context(session_codec_error::CodecSnafu)?;
        stream
            .encode_one(self.error_message)
            .await
            .context(session_codec_error::CodecSnafu)?;
        stream
            .encode_one(self.language_tag)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for PtyRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            term_type: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
            width_cols: stream
                .decode_one()
                .await
                .context(session_codec_error::ReadIoSnafu)?,
            height_rows: stream
                .decode_one()
                .await
                .context(session_codec_error::ReadIoSnafu)?,
            width_px: stream
                .decode_one()
                .await
                .context(session_codec_error::ReadIoSnafu)?,
            height_px: stream
                .decode_one()
                .await
                .context(session_codec_error::ReadIoSnafu)?,
            terminal_modes: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for PtyRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.term_type)
            .await
            .context(session_codec_error::CodecSnafu)?;
        stream
            .encode_one(self.width_cols)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.height_rows)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.width_px)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.height_px)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.terminal_modes)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for WindowChangeRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let width_cols: VarInt = stream
            .decode_one()
            .await
            .context(session_codec_error::ReadIoSnafu)?;
        let height_rows: VarInt = stream
            .decode_one()
            .await
            .context(session_codec_error::ReadIoSnafu)?;
        let width_px: VarInt = stream
            .decode_one()
            .await
            .context(session_codec_error::ReadIoSnafu)?;
        let height_px: VarInt = stream
            .decode_one()
            .await
            .context(session_codec_error::ReadIoSnafu)?;
        Ok(Self {
            width_cols,
            height_rows,
            width_px,
            height_px,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for WindowChangeRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.width_cols)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.height_rows)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.width_px)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        stream
            .encode_one(self.height_px)
            .await
            .context(session_codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SignalRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            signal_name: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for SignalRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.signal_name)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for EnvRequest {
    type Error = SessionCodecError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        Ok(Self {
            name: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
            value: stream
                .decode_one()
                .await
                .context(session_codec_error::CodecSnafu)?,
        })
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for EnvRequest {
    type Output = ();
    type Error = SessionCodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        let mut stream = pin!(stream);
        stream
            .encode_one(self.name)
            .await
            .context(session_codec_error::CodecSnafu)?;
        stream
            .encode_one(self.value)
            .await
            .context(session_codec_error::CodecSnafu)?;
        Ok(())
    }
}

// ===========================================================================
// WantReplyChannelRequest / NotifyChannelRequest implementations
// ===========================================================================

/// Channel request `"pty-req"` — allocate a pseudo-terminal.
#[derive(Debug, Clone)]
pub struct PtyChannelRequest {
    pub payload: PtyRequest,
}

impl WantReplyChannelRequest for PtyChannelRequest {
    type Success = EmptyPayload;
    type Payload = PtyRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("pty-req")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel request `"exec"` — execute a command.
#[derive(Debug, Clone)]
pub struct ExecChannelRequest {
    pub payload: ExecRequest,
}

impl WantReplyChannelRequest for ExecChannelRequest {
    type Success = EmptyPayload;
    type Payload = ExecRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("exec")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel request `"shell"` — start an interactive shell.
#[derive(Debug, Clone)]
pub struct ShellChannelRequest;

impl WantReplyChannelRequest for ShellChannelRequest {
    type Success = EmptyPayload;
    type Payload = EmptyPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("shell")
    }

    fn payload(&self) -> &Self::Payload {
        &EmptyPayload
    }
}

/// Channel request `"subsystem"` — start a subsystem.
#[derive(Debug, Clone)]
pub struct SubsystemChannelRequest {
    pub payload: SubsystemRequest,
}

impl WantReplyChannelRequest for SubsystemChannelRequest {
    type Success = EmptyPayload;
    type Payload = SubsystemRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("subsystem")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel request `"signal"` — send a signal to the remote process.
#[derive(Debug, Clone)]
pub struct SignalChannelRequest {
    pub payload: SignalRequest,
}

impl WantReplyChannelRequest for SignalChannelRequest {
    type Success = EmptyPayload;
    type Payload = SignalRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("signal")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"signal"` — send signal without expecting reply.
#[derive(Debug, Clone)]
pub struct SignalChannelNotice {
    pub payload: SignalRequest,
}

impl NotifyChannelRequest for SignalChannelNotice {
    type Payload = SignalRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("signal")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"window-change"` — terminal size changed (no reply).
#[derive(Debug, Clone)]
pub struct WindowChangeChannelNotice {
    pub payload: WindowChangeRequest,
}

impl NotifyChannelRequest for WindowChangeChannelNotice {
    type Payload = WindowChangeRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("window-change")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"exit-status"` — process exited (no reply).
#[derive(Debug, Clone)]
pub struct ExitStatusChannelNotice {
    pub payload: ExitStatusRequest,
}

impl NotifyChannelRequest for ExitStatusChannelNotice {
    type Payload = ExitStatusRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("exit-status")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Channel notification `"exit-signal"` — process killed by signal (no reply).
#[derive(Debug, Clone)]
pub struct ExitSignalChannelNotice {
    pub payload: ExitSignalRequest,
}

impl NotifyChannelRequest for ExitSignalChannelNotice {
    type Payload = ExitSignalRequest;

    fn request_type(&self) -> SshString {
        SshString::from_static("exit-signal")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// Serializable error type for RTC method returns.
///
/// This type crosses process boundaries via remoc, so it must be fully serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionError {
    Message(String),
    Io(IoErrorKind),
    Remote(remoc::rtc::CallError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Io(kind) => kind.fmt(f),
            Self::Remote(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Remote(error) => Some(error),
            Self::Message(_) | Self::Io(_) => None,
        }
    }
}

impl From<remoc::rtc::CallError> for SessionError {
    fn from(err: remoc::rtc::CallError) -> Self {
        Self::Remote(err)
    }
}

impl From<std::io::Error> for SessionError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.kind().into())
    }
}

impl SessionError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    Other,
}

impl std::fmt::Display for IoErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NotFound => "not found",
            Self::PermissionDenied => "permission denied",
            Self::ConnectionRefused => "connection refused",
            Self::ConnectionReset => "connection reset",
            Self::HostUnreachable => "host unreachable",
            Self::NetworkUnreachable => "network unreachable",
            Self::ConnectionAborted => "connection aborted",
            Self::NotConnected => "not connected",
            Self::AddrInUse => "address in use",
            Self::AddrNotAvailable => "address not available",
            Self::NetworkDown => "network down",
            Self::BrokenPipe => "broken pipe",
            Self::AlreadyExists => "already exists",
            Self::WouldBlock => "operation would block",
            Self::InvalidInput => "invalid input",
            Self::InvalidData => "invalid data",
            Self::TimedOut => "timed out",
            Self::WriteZero => "write zero",
            Self::Interrupted => "interrupted",
            Self::Unsupported => "unsupported",
            Self::UnexpectedEof => "unexpected end of file",
            Self::OutOfMemory => "out of memory",
            Self::Other => "other I/O error",
        };
        f.write_str(name)
    }
}

impl From<std::io::ErrorKind> for IoErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            std::io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            std::io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            std::io::ErrorKind::ConnectionAborted => Self::ConnectionAborted,
            std::io::ErrorKind::NotConnected => Self::NotConnected,
            std::io::ErrorKind::AddrInUse => Self::AddrInUse,
            std::io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            std::io::ErrorKind::NetworkDown => Self::NetworkDown,
            std::io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            std::io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            std::io::ErrorKind::WouldBlock => Self::WouldBlock,
            std::io::ErrorKind::InvalidInput => Self::InvalidInput,
            std::io::ErrorKind::InvalidData => Self::InvalidData,
            std::io::ErrorKind::TimedOut => Self::TimedOut,
            std::io::ErrorKind::WriteZero => Self::WriteZero,
            std::io::ErrorKind::Interrupted => Self::Interrupted,
            std::io::ErrorKind::Unsupported => Self::Unsupported,
            std::io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            std::io::ErrorKind::OutOfMemory => Self::OutOfMemory,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "server")]
    #[test]
    fn auth_request_roundtrip() {
        let req = AuthRequest {
            username: "alice".into(),
            credential: crate::auth::AuthCredential::Basic {
                username: "alice".into(),
                password: "secret".into(),
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: AuthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.username, "alice");
    }

    #[cfg(feature = "server")]
    #[test]
    fn auth_error_display() {
        let err = AuthError::PamFailed {
            reason: "invalid password".into(),
        };
        assert_eq!(
            err.to_string(),
            "PAM authentication failed: invalid password"
        );

        let err = AuthError::UserNotFound {
            username: "nobody".into(),
        };
        assert_eq!(err.to_string(), "user not found: nobody");
    }

    #[cfg(feature = "server")]
    #[test]
    fn session_run_error_display() {
        let err = SessionRunError::DropPrivileges {
            reason: "setuid failed".into(),
        };
        assert_eq!(err.to_string(), "failed to drop privileges: setuid failed");
    }

    #[test]
    fn session_error_display() {
        let err = SessionError::new("something went wrong");
        assert_eq!(err.to_string(), "something went wrong");
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn session_error_roundtrip() {
        let err = SessionError::new("test error");
        let json = serde_json::to_string(&err).unwrap();
        let decoded: SessionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err.to_string(), decoded.to_string());
    }
}
