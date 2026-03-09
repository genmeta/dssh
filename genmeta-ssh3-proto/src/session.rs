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
    async fn run_session(&self, init: SessionInit) -> Result<(), SessionError>;
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
}
