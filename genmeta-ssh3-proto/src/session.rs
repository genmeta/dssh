//! SSH3 session types and transport trait for cross-process communication.
//!
//! The [`Ssh3Transport`] trait is marked with `#[remoc::rtc::remote]`, which generates:
//! - [`Ssh3TransportClient`] — serializable proxy sent to the child process
//! - [`Ssh3TransportServer`] / [`Ssh3TransportServerShared`] / [`Ssh3TransportServerSharedMut`] —
//!   wrappers for serving the trait implementation
//!
//! The main server process implements the trait and serves it; the child
//! process uses the client to accept and open channels.

use std::path::PathBuf;

use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Information needed to initialize an SSH3 session in the child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInit {
    /// Unique conversation identifier for this session.
    #[serde(
        serialize_with = "serialize_stream_id",
        deserialize_with = "deserialize_stream_id"
    )]
    pub conversation_id: StreamId,
    /// Authenticated username.
    pub username: String,
    /// POSIX user ID.
    pub uid: u32,
    /// POSIX group ID.
    pub gid: u32,
    /// User's home directory.
    pub home: PathBuf,
    /// User's login shell.
    pub shell: PathBuf,
}

/// Result of PAM authentication performed by the main process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthResult {
    /// Authentication succeeded.
    Success {
        /// POSIX user ID.
        uid: u32,
        /// POSIX group ID.
        gid: u32,
        /// User's home directory.
        home: PathBuf,
        /// User's login shell.
        shell: PathBuf,
    },
    /// Authentication failed.
    Failure {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

/// Bootstrap payload sent from parent to child process.
/// Contains the transport client for pulling channels and the credential for PAM auth.
#[derive(Serialize, Deserialize)]
pub struct ChildBootstrap {
    pub transport: Ssh3TransportClient,
    pub credential: crate::auth::AuthCredential,
    #[serde(
        serialize_with = "serialize_stream_id",
        deserialize_with = "deserialize_stream_id"
    )]
    pub conversation_id: StreamId,
}

fn serialize_stream_id<S>(stream_id: &StreamId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(stream_id.into_inner())
}

fn deserialize_stream_id<'de, D>(deserializer: D) -> Result<StreamId, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = u64::deserialize(deserializer)?;
    let varint = VarInt::try_from(raw).map_err(serde::de::Error::custom)?;
    Ok(StreamId(varint))
}

/// Serializable error type for RTC method returns.
///
/// This type crosses process boundaries via remoc, so it must be fully serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionError {
    Message(String),
    Io(IoErrorKind),
    Transport(TransportError),
    Remote(remoc::rtc::CallError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => f.write_str(message),
            Self::Io(kind) => kind.fmt(f),
            Self::Transport(error) => error.fmt(f),
            Self::Remote(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
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

impl From<TransportError> for SessionError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
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

/// Serializable error type for transport-level RTC method returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportError {
    ChannelClosed(String),
    OpenFailed(String),
    Timeout,
    Other(String),
    Remote(remoc::rtc::CallError),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelClosed(msg) => f.write_str(msg),
            Self::OpenFailed(msg) => f.write_str(msg),
            Self::Timeout => write!(f, "timeout"),
            Self::Other(msg) => f.write_str(msg),
            Self::Remote(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Remote(error) => Some(error),
            Self::ChannelClosed(_) | Self::OpenFailed(_) | Self::Timeout | Self::Other(_) => None,
        }
    }
}

impl From<remoc::rtc::CallError> for TransportError {
    fn from(err: remoc::rtc::CallError) -> Self {
        Self::Remote(err)
    }
}

/// RTC trait for SSH3 transport-level channel management.
///
/// The `#[remoc::rtc::remote]` macro generates `Ssh3TransportClient`,
/// `Ssh3TransportServer`, `Ssh3TransportServerShared`, and `Ssh3TransportServerSharedMut`.
#[remoc::rtc::remote]
pub trait Ssh3Transport: Sync {
    /// Accept an incoming channel from the remote peer.
    ///
    /// Returns `Ok(None)` when no more channels will arrive (connection closed).
    async fn accept_channel(&self) -> Result<
        Option<(crate::codec::ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
        TransportError,
    >;

    /// Open a new channel toward the remote peer.
    ///
    /// If `header` is `None`, no header is written to the underlying stream.
    async fn open_channel(
        &self,
        header: Option<crate::codec::ChannelHeader>,
    ) -> Result<
        (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
        TransportError,
    >;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_init_roundtrip() {
        let init = SessionInit {
            conversation_id: StreamId::try_from(42u64).unwrap(),
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        };
        let json = serde_json::to_string(&init).unwrap();
        let decoded: SessionInit = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.conversation_id, StreamId::try_from(42u64).unwrap());
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.uid, 1000);
        assert_eq!(decoded.gid, 1000);
        assert_eq!(decoded.home, PathBuf::from("/home/alice"));
        assert_eq!(decoded.shell, PathBuf::from("/bin/bash"));
    }

    #[test]
    fn auth_result_success_roundtrip() {
        let result = AuthResult::Success {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/bob"),
            shell: PathBuf::from("/bin/zsh"),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: AuthResult = serde_json::from_str(&json).unwrap();
        match decoded {
            AuthResult::Success {
                uid,
                gid,
                home,
                shell,
            } => {
                assert_eq!(uid, 1000);
                assert_eq!(gid, 1000);
                assert_eq!(home, PathBuf::from("/home/bob"));
                assert_eq!(shell, PathBuf::from("/bin/zsh"));
            }
            AuthResult::Failure { .. } => panic!("expected Success"),
        }
    }

    #[test]
    fn auth_result_failure_roundtrip() {
        let result = AuthResult::Failure {
            reason: "invalid password".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: AuthResult = serde_json::from_str(&json).unwrap();
        match decoded {
            AuthResult::Failure { reason } => assert_eq!(reason, "invalid password"),
            AuthResult::Success { .. } => panic!("expected Failure"),
        }
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

    #[test]
    fn ssh3_transport_client_type_exists() {
        fn assert_send<T: Send>() {}
        assert_send::<Ssh3TransportClient>();
    }

    #[test]
    fn ssh3_transport_server_types_exist() {
        // Ssh3TransportServerShared<T> requires a concrete impl type.
        // Create a trivial one to verify the generated type exists and is Send.
        struct Dummy;
        impl Ssh3Transport for Dummy {
            async fn accept_channel(&self) -> Result<
                Option<(crate::codec::ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
                TransportError,
            > { Ok(None) }
            async fn open_channel(&self, _: Option<crate::codec::ChannelHeader>) -> Result<
                (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
                TransportError,
            > { Err(TransportError::Other("dummy".into())) }
        }
        fn assert_send<T: Send>() {}
        assert_send::<Ssh3TransportServerShared<Dummy>>();
    }

    #[test]
    fn transport_error_roundtrip() {
        let cases = vec![
            TransportError::ChannelClosed("gone".into()),
            TransportError::OpenFailed("refused".into()),
            TransportError::Timeout,
            TransportError::Other("oops".into()),
        ];
        for err in &cases {
            let json = serde_json::to_string(err).unwrap();
            let decoded: TransportError = serde_json::from_str(&json).unwrap();
            assert_eq!(err.to_string(), decoded.to_string());
        }
    }

}
