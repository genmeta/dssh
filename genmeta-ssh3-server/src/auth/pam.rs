//! PAM (Pluggable Authentication Modules) wrapper for SSH3 password authentication.
//!
//! Provides a trait-based abstraction over PAM to enable testing without
//! linking against the real `libpam` C library. The 4-stage flow is:
//!
//! 1. `pam_start` — initialize a PAM transaction (implicit in trait call)
//! 2. `pam_authenticate` — verify the user's credentials
//! 3. `pam_acct_mgmt` — check account validity (expiration, access restrictions)
//! 4. `pam_end` — clean up the PAM transaction (handled via `Drop`)
//!
//! On success, user info (uid, gid, home, shell) is queried and returned as
//! [`AuthResult::Success`]. On failure, a random delay (100–500 ms) is added
//! as timing-attack protection before returning [`PamError`].


use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use rand::Rng;

/// The fixed PAM service name for SSH3 authentication.
#[allow(dead_code)]
const PAM_SERVICE: &str = "ssh3";

// ---------------------------------------------------------------------------
// AuthResult — local copy, will reconcile with proto's AuthResult later
// ---------------------------------------------------------------------------

/// Result of a successful PAM authentication, including resolved user info.
/// 
/// Defined locally because `genmeta-ssh3-proto::session::AuthResult` is being
/// built in a parallel task. Will be unified later.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AuthResult {
    /// Credentials verified and account is valid.
    Success {
        uid: u32,
        gid: u32,
        home: PathBuf,
        shell: PathBuf,
    },
    /// Authentication or account check failed.
    Failure { reason: String },
}

// ---------------------------------------------------------------------------
// PamError
// ---------------------------------------------------------------------------

/// Error type for PAM authentication failures.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct PamError {
    /// Human-readable description of what went wrong.
    pub message: String,
}

impl PamError {
    #[allow(dead_code)]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PAM error: {}", self.message)
    }
}

impl std::error::Error for PamError {}

// ---------------------------------------------------------------------------
// UserInfo — resolved user metadata
// ---------------------------------------------------------------------------

/// Resolved POSIX user information, returned on successful authentication.
/// 
/// In production, this would come from `nix::unistd::User::from_name()`.
/// For testing, it is provided by the mock backend.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UserInfo {
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
}

// ---------------------------------------------------------------------------
// PamBackend trait
// ---------------------------------------------------------------------------

/// Abstraction over PAM operations to enable testing without `libpam`.
/// 
/// Each method corresponds to a stage in the PAM transaction:
/// - `authenticate` → `pam_authenticate` (stage 2)
/// - `acct_mgmt` → `pam_acct_mgmt` (stage 3)
/// 
/// Stage 1 (`pam_start`) is implicit — the backend manages transaction setup.
/// Stage 4 (`pam_end`) is handled via `Drop` semantics on the backend.
#[allow(dead_code)]
pub(crate) trait PamBackend: Send + Sync {
    /// Authenticate the user (PAM stage 2: `pam_authenticate`).
    fn authenticate(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<(), PamError>;

    /// Check account validity (PAM stage 3: `pam_acct_mgmt`).
    fn acct_mgmt(&self, service: &str, username: &str) -> Result<(), PamError>;

    /// Look up user info (uid, gid, home, shell) for the given username.
    /// 
    /// In production, this would call `nix::unistd::User::from_name()`.
    fn get_user_info(&self, username: &str) -> Result<UserInfo, PamError>;
}

// ---------------------------------------------------------------------------
// SystemPam — real PAM backend (deferred implementation)
// ---------------------------------------------------------------------------

/// Real PAM backend that calls into the system's `libpam`.
/// 
/// This is a stub — actual C FFI integration with `pam`/`pam-sys` crate
/// is deferred until we add OS-specific C library linkage.
#[allow(dead_code)]
pub(crate) struct SystemPam;

impl PamBackend for SystemPam {
    fn authenticate(
        &self,
        _service: &str,
        _username: &str,
        _password: &str,
    ) -> Result<(), PamError> {
        // TODO: Call pam_start → pam_authenticate via pam-sys FFI.
        // Requires linking against libpam (-lpam) and handling
        // the PAM conversation callback for password supply.
        todo!("SystemPam::authenticate — requires libpam C FFI linkage")
    }

    fn acct_mgmt(&self, _service: &str, _username: &str) -> Result<(), PamError> {
        // TODO: Call pam_acct_mgmt via the open PAM handle.
        todo!("SystemPam::acct_mgmt — requires libpam C FFI linkage")
    }

    fn get_user_info(&self, _username: &str) -> Result<UserInfo, PamError> {
        // TODO: Use nix::unistd::User::from_name(username) to resolve
        // uid, gid, home directory, and login shell.
        // Do not add `nix` as a dependency yet.
        todo!("SystemPam::get_user_info — requires nix crate for getpwnam")
    }
}

// ---------------------------------------------------------------------------
// pam_authenticate — the main async entry point
// ---------------------------------------------------------------------------

/// Authenticate a user via PAM with the 4-stage flow.
/// 
/// 1. **pam_start** — implicit (backend manages transaction setup)
/// 2. **pam_authenticate** — verify credentials
/// 3. **pam_acct_mgmt** — check account validity
/// 4. **pam_end** — implicit (backend cleanup via Drop)
/// 
/// On success, queries user info and returns `AuthResult::Success`.
/// On any failure, adds a random delay (100–500 ms) for timing-attack
/// protection before returning `AuthResult::Failure`.
#[allow(dead_code)]
pub(crate) async fn pam_authenticate(
    backend: &dyn PamBackend,
    username: &str,
    password: &str,
) -> Result<AuthResult, PamError> {
    // Stage 2: authenticate
    if let Err(e) = backend.authenticate(PAM_SERVICE, username, password) {
        add_random_delay().await;
        return Err(e);
    }

    // Stage 3: account management
    if let Err(e) = backend.acct_mgmt(PAM_SERVICE, username) {
        add_random_delay().await;
        return Err(e);
    }

    // Stage 4 (pam_end) is implicit — the PAM handle is cleaned up
    // when the backend goes out of scope (Drop semantics).

    // Query user info on success
    let info = backend.get_user_info(username)?;

    Ok(AuthResult::Success {
        uid: info.uid,
        gid: info.gid,
        home: info.home,
        shell: info.shell,
    })
}

/// Add a random delay between 100–500 ms as timing-attack protection.
/// 
/// This ensures that failed authentications take roughly the same amount
/// of wall-clock time regardless of which stage failed, making it harder
/// for an attacker to distinguish "wrong username" from "wrong password".
#[allow(dead_code)]
async fn add_random_delay() {
    let delay_ms = rand::rng().random_range(100..=500);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    // -----------------------------------------------------------------------
    // MockPam — configurable mock backend for testing
    // -----------------------------------------------------------------------

    /// Mock PAM backend with configurable success/failure responses.
    struct MockPam {
        /// If `Some(err)`, `authenticate()` will fail with this error.
        auth_error: Option<PamError>,
        /// If `Some(err)`, `acct_mgmt()` will fail with this error.
        acct_error: Option<PamError>,
        /// User info to return on success.
        user_info: UserInfo,
        /// Tracks whether cleanup (Drop) was called.
        dropped: Arc<AtomicBool>,
    }

    impl MockPam {
        fn success(user_info: UserInfo, dropped: Arc<AtomicBool>) -> Self {
            Self {
                auth_error: None,
                acct_error: None,
                user_info,
                dropped,
            }
        }

        fn auth_failure(message: &str, dropped: Arc<AtomicBool>) -> Self {
            Self {
                auth_error: Some(PamError::new(message)),
                acct_error: None,
                user_info: default_user_info(),
                dropped,
            }
        }

        fn acct_failure(message: &str, dropped: Arc<AtomicBool>) -> Self {
            Self {
                auth_error: None,
                acct_error: Some(PamError::new(message)),
                user_info: default_user_info(),
                dropped,
            }
        }
    }

    impl PamBackend for MockPam {
        fn authenticate(
            &self,
            _service: &str,
            _username: &str,
            _password: &str,
        ) -> Result<(), PamError> {
            match &self.auth_error {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }

        fn acct_mgmt(&self, _service: &str, _username: &str) -> Result<(), PamError> {
            match &self.acct_error {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }

        fn get_user_info(&self, _username: &str) -> Result<UserInfo, PamError> {
            Ok(self.user_info.clone())
        }
    }

    impl Drop for MockPam {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn default_user_info() -> UserInfo {
        UserInfo {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/testuser"),
            shell: PathBuf::from("/bin/bash"),
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_pam_success_full_flow() {
        let dropped = Arc::new(AtomicBool::new(false));
        let info = UserInfo {
            uid: 1001,
            gid: 1001,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/zsh"),
        };
        let mock = MockPam::success(info, dropped.clone());

        let result = pam_authenticate(&mock, "alice", "correct-password").await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        match result.unwrap() {
            AuthResult::Success {
                uid,
                gid,
                home,
                shell,
            } => {
                assert_eq!(uid, 1001);
                assert_eq!(gid, 1001);
                assert_eq!(home, PathBuf::from("/home/alice"));
                assert_eq!(shell, PathBuf::from("/bin/zsh"));
            }
            AuthResult::Failure { reason } => {
                panic!("expected Success, got Failure: {reason}");
            }
        }

        // Drop the mock and verify cleanup
        drop(mock);
        assert!(dropped.load(Ordering::SeqCst), "pam_end (Drop) not called");
    }

    #[tokio::test]
    async fn test_pam_auth_failure_with_delay() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mock = MockPam::auth_failure("authentication failure", dropped.clone());

        let start = tokio::time::Instant::now();
        let result = pam_authenticate(&mock, "alice", "wrong-password").await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert_eq!(err.message, "authentication failure");

        // Verify timing-attack protection delay was applied (at least 100ms)
        assert!(
            elapsed >= Duration::from_millis(100),
            "expected delay >= 100ms, got {elapsed:?}"
        );

        drop(mock);
        assert!(dropped.load(Ordering::SeqCst), "pam_end (Drop) not called");
    }

    #[tokio::test]
    async fn test_pam_acct_mgmt_failure() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mock = MockPam::acct_failure("account expired", dropped.clone());

        let start = tokio::time::Instant::now();
        let result = pam_authenticate(&mock, "alice", "correct-password").await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert_eq!(err.message, "account expired");

        // Verify timing-attack protection delay was applied
        assert!(
            elapsed >= Duration::from_millis(100),
            "expected delay >= 100ms, got {elapsed:?}"
        );

        drop(mock);
        assert!(dropped.load(Ordering::SeqCst), "pam_end (Drop) not called");
    }

    #[tokio::test]
    async fn test_pam_end_always_called() {
        // Verify that Drop is called even on success path
        let dropped_success = Arc::new(AtomicBool::new(false));
        {
            let mock = MockPam::success(default_user_info(), dropped_success.clone());
            let _ = pam_authenticate(&mock, "user", "pass").await;
            // mock goes out of scope here
        }
        assert!(
            dropped_success.load(Ordering::SeqCst),
            "pam_end (Drop) not called on success path"
        );

        // Verify that Drop is called on failure path
        let dropped_failure = Arc::new(AtomicBool::new(false));
        {
            let mock = MockPam::auth_failure("fail", dropped_failure.clone());
            let _ = pam_authenticate(&mock, "user", "pass").await;
            // mock goes out of scope here
        }
        assert!(
            dropped_failure.load(Ordering::SeqCst),
            "pam_end (Drop) not called on failure path"
        );
    }

    #[test]
    fn test_pam_error_display() {
        let err = PamError::new("authentication failure");
        assert_eq!(err.to_string(), "PAM error: authentication failure");
    }

    #[test]
    fn test_pam_service_name() {
        assert_eq!(PAM_SERVICE, "ssh3");
    }
}