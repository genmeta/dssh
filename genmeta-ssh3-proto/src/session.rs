//! SSH3 session RTC trait for cross-process communication.
//!
//! The [`SshSession`] trait is marked with `#[remoc::rtc::remote]`, which generates:
//! - [`SshSessionClient`] — serializable proxy sent to the child process
//! - [`SshSessionServer`] / [`SshSessionServerShared`] / [`SshSessionServerSharedMut`] —
//!   wrappers for serving the trait implementation
//!
//! The main server process calls `run_session()` via the client, and the child
//! process implements the trait and serves it via the server wrapper.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Information needed to initialize an SSH3 session in the child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInit {
    /// Unique conversation identifier for this session.
    pub conversation_id: u64,
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
}

/// Serializable error type for RTC method returns.
///
/// Uses a simple string wrapper because `snafu` errors are not `Serialize`/`Deserialize`.
/// This type crosses process boundaries via remoc, so it must be fully serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionError {
    /// Error message.
    pub message: String,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionError {}

impl From<remoc::rtc::CallError> for SessionError {
    fn from(err: remoc::rtc::CallError) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl SessionError {
    /// Create a new `SessionError` from any displayable value.
    pub fn new(msg: impl std::fmt::Display) -> Self {
        Self {
            message: msg.to_string(),
        }
    }
}


/// RTC trait for cross-process SSH3 session management.
///
/// The `#[remoc::rtc::remote]` macro generates `SshSessionClient`,
/// `SshSessionServer`, `SshSessionServerShared`, and `SshSessionServerSharedMut`.
#[remoc::rtc::remote]
pub trait SshSession: Sync {
    /// Run the SSH3 session with the given initialization parameters.
    ///
    /// Called by the main server process on the child process via RTC.
    /// The child process sets up the PTY, shell, and channel handling,
    /// then runs until the session terminates.
    ///
    /// `from_client` receives raw bytes from the SSH client (stdin/channel data).
    /// `to_client` sends raw bytes back to the SSH client (stdout/channel data).
    /// `parent` provides the parent-side RTC service for requesting new channels.
    async fn run_session(
        &self,
        init: SessionInit,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
        parent: ParentServiceClient,
    ) -> Result<(), SessionError>;


    /// Handle a non-session channel (forwarding, global-request, etc.).
    ///
    /// The parent calls this for each non-session channel, passing the typed
    /// `ChannelHeader` and raw byte channel endpoints. The child dispatches
    /// to the appropriate handler based on the header's channel type.
    async fn handle_channel(
        &self,
        header: crate::codec::ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), SessionError>;
}

/// Service provided by the parent process to the child session.
/// Enables the child to request the parent to open new QUIC channels
/// (e.g., for reverse TCP forwarding or reverse streamlocal forwarding).
#[remoc::rtc::remote]
pub trait ParentService: Sync {
    /// Open a new channel on behalf of the child.
    /// The parent opens a QUIC stream, optionally writes a ChannelHeader,
    /// and returns remoc mpsc endpoints bridged to the QUIC stream.
    ///
    /// If `header` is `None`, no header is written to the QUIC stream
    /// (the caller is expected to write its own header/data after getting
    /// the reader/writer). This matches the current `build_stream_factory`
    /// behavior where the header argument is `None`.
    async fn open_channel(
        &self,
        header: Option<crate::codec::ChannelHeader>,
    ) -> Result<
        (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
        SessionError,
    >;
}

/// Serializable error type for transport-level RTC method returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportError {
    ChannelClosed(String),
    OpenFailed(String),
    Timeout,
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelClosed(msg) => write!(f, "channel closed: {msg}"),
            Self::OpenFailed(msg) => write!(f, "open failed: {msg}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<remoc::rtc::CallError> for TransportError {
    fn from(err: remoc::rtc::CallError) -> Self {
        Self::Other(err.to_string())
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
            conversation_id: 42,
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        };
        let json = serde_json::to_string(&init).unwrap();
        let decoded: SessionInit = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.conversation_id, 42);
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
        let err = SessionError {
            message: "test error".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: SessionError = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.message, "test error");
    }

    /// Verify that the RTC macro generated the expected client type.
    /// `SshSessionClient` must be constructible (it's generated by the macro).
    #[test]
    fn rtc_client_type_exists() {
        // SshSessionClient is generated by #[remoc::rtc::remote].
        // We verify the type exists and is Serialize + Deserialize by
        // checking it can be named and its trait bounds hold.
        fn assert_serializable<T: Serialize + for<'de> Deserialize<'de>>() {}
        assert_serializable::<SshSessionClient>();
    }

    /// Verify that the RTC macro generated the server wrapper types.
    #[test]
    fn rtc_server_types_exist() {
        // These types are generated by the macro — if they don't exist,
        // this test fails at compile time.
        fn assert_send<T: Send>() {}
        assert_send::<SshSessionServerShared<()>>();
        assert_send::<SshSessionServerSharedMut<()>>();
    }

    /// Verify that the RTC macro generated the ParentServiceClient type.
    #[test]
    fn parent_service_client_type_exists() {
        fn assert_serializable<T: Serialize + for<'de> Deserialize<'de>>() {}
        assert_serializable::<ParentServiceClient>();
    }

    /// Verify that the RTC macro generated the ParentService server wrapper types.
    #[test]
    fn parent_service_server_types_exist() {
        fn assert_send<T: Send>() {}
        assert_send::<ParentServiceServerShared<()>>();
        assert_send::<ParentServiceServerSharedMut<()>>();
    }
}
