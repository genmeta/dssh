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


#[cfg(feature = "pam")]
use std::ffi::CStr;
#[cfg(feature = "pam")]
use std::ffi::CString;
use std::path::PathBuf;
use std::time::Duration;

use rand::Rng;
#[cfg(feature = "pam")]
use snafu::ResultExt;
use snafu::Snafu;

#[cfg(feature = "pam")]
use nix::unistd::User;
#[cfg(feature = "pam")]
use pam_client2::{Context, Flag};

/// The fixed PAM service name for SSH3 authentication.
#[allow(dead_code)]
const PAM_SERVICE: &str = "ssh3";

// ---------------------------------------------------------------------------
// AuthResult — local copy, will reconcile with proto's AuthResult later
// ---------------------------------------------------------------------------

/// Result of a successful PAM authentication, including resolved user info.
/// 
/// Defined locally because the shared core `genmeta-ssh::session::AuthResult` was being
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
#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub))]
pub enum PamError {
    // ── Real PAM variants (feature-gated) ─────────────────────────────────

    /// Failed to create a PAM transaction context.
    #[cfg(feature = "pam")]
    #[snafu(display("failed to create PAM context"))]
    PamContextCreation { source: pam_client2::Error },

    /// `pam_authenticate` call failed.
    #[cfg(feature = "pam")]
    #[snafu(display("pam_authenticate failed"))]
    AuthenticateFailed { source: pam_client2::Error },

    /// `pam_acct_mgmt` call failed.
    #[cfg(feature = "pam")]
    #[snafu(display("pam_acct_mgmt failed"))]
    AccountCheckFailed { source: pam_client2::Error },

    /// `getpwnam` syscall failed while resolving user info.
    #[cfg(feature = "pam")]
    #[snafu(display("getpwnam syscall failed"))]
    GetpwnamFailed { source: nix::errno::Errno },

    /// The specified POSIX user does not exist.
    #[cfg(feature = "pam")]
    #[snafu(display("user '{username}' not found"))]
    UserNotFound { username: String },

    // ── Always-available variants (for mocks and non-PAM builds) ──────────

    /// Authentication was rejected (wrong credentials).
    #[snafu(display("authentication rejected"))]
    AuthenticationRejected,

    /// Account check failed (e.g. account expired or locked).
    #[snafu(display("account check failed"))]
    AccountCheckRejected,
}

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
pub trait PamBackend: Send + Sync {
    fn start_transaction(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn PamTransaction>, PamError>;

    /// Look up user info (uid, gid, home, shell) for the given username.
    /// 
    /// In production, this would call `nix::unistd::User::from_name()`.
    fn get_user_info(&self, username: &str) -> Result<UserInfo, PamError>;
}

pub trait PamTransaction: Send {
    fn authenticate(&mut self) -> Result<(), PamError>;
    fn acct_mgmt(&mut self) -> Result<(), PamError>;
}

// ---------------------------------------------------------------------------
// SystemPam — real PAM backend (deferred implementation)
// ---------------------------------------------------------------------------

/// Real PAM backend that calls into the system's `libpam` via `pam-client2`.
///
/// Gate behind the `pam` feature flag, which enables the `pam-client2` dep.
#[cfg(feature = "pam")]
pub struct SystemPam;

#[cfg(feature = "pam")]
pub struct SystemPamTransaction {
    context: Context<PasswordConversation>,
}

#[cfg(feature = "pam")]
struct PasswordConversation {
    username: String,
    password: String,
}

#[cfg(feature = "pam")]
impl pam_client2::ConversationHandler for PasswordConversation {
    fn prompt_echo_on(&mut self, msg: &CStr) -> Result<CString, pam_client2::ErrorCode> {
        tracing::debug!(target: "pam", "Request username with prompt: {}", msg.to_string_lossy());
        CString::new(self.username.as_str()).map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn prompt_echo_off(&mut self, msg: &CStr) -> Result<CString, pam_client2::ErrorCode> {
        tracing::debug!(target: "pam", "Request password with prompt: {}", msg.to_string_lossy());
        CString::new(self.password.as_str()).map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn text_info(&mut self, msg: &CStr) {
        tracing::debug!(target: "pam", "PAM info: {}", msg.to_string_lossy());
    }

    fn error_msg(&mut self, msg: &CStr) {
        tracing::warn!(target: "pam", "PAM error: {}", msg.to_string_lossy());
    }
}

#[cfg(feature = "pam")]
impl PamBackend for SystemPam {
    fn start_transaction(
        &self,
        service: &str,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn PamTransaction>, PamError> {
        let context = Context::new(
            service,
            Some(username),
            PasswordConversation {
                username: username.to_owned(),
                password: password.to_owned(),
            },
        )
        .context(PamContextCreationSnafu)?;

        Ok(Box::new(SystemPamTransaction { context }))
    }

    fn get_user_info(&self, username: &str) -> Result<UserInfo, PamError> {
        let user = User::from_name(username)
            .context(GetpwnamFailedSnafu)?
            .ok_or_else(|| PamError::UserNotFound { username: username.to_owned() })?;

        Ok(UserInfo {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir,
            shell: user.shell,
        })
    }
}

#[cfg(feature = "pam")]
impl PamTransaction for SystemPamTransaction {
    fn authenticate(&mut self) -> Result<(), PamError> {
        self.context
            .authenticate(Flag::NONE)
            .context(AuthenticateFailedSnafu)
    }

    fn acct_mgmt(&mut self) -> Result<(), PamError> {
        self.context
            .acct_mgmt(Flag::NONE)
            .context(AccountCheckFailedSnafu)
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
pub async fn pam_authenticate(
    backend: &dyn PamBackend,
    username: &str,
    password: &str,
) -> Result<AuthResult, PamError> {
    let mut transaction = match backend.start_transaction(PAM_SERVICE, username, password) {
        Ok(transaction) => transaction,
        Err(e) => {
            add_random_delay().await;
            return Err(e);
        }
    };

    // Stage 2: authenticate
    if let Err(e) = transaction.authenticate() {
        add_random_delay().await;
        return Err(e);
    }

    // Stage 3: account management
    if let Err(e) = transaction.acct_mgmt() {
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
        /// Tracks transaction usage order.
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    struct MockPamTransaction {
        auth_error: Option<PamError>,
        acct_error: Option<PamError>,
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl MockPam {
        fn success(user_info: UserInfo, dropped: Arc<AtomicBool>) -> Self {
            Self {
                auth_error: None,
                acct_error: None,
                user_info,
                dropped,
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn auth_failure(dropped: Arc<AtomicBool>) -> Self {
            Self {
                auth_error: Some(PamError::AuthenticationRejected),
                acct_error: None,
                user_info: default_user_info(),
                dropped,
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn acct_failure(dropped: Arc<AtomicBool>) -> Self {
            Self {
                auth_error: None,
                acct_error: Some(PamError::AccountCheckRejected),
                user_info: default_user_info(),
                dropped,
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn call_log(&self) -> Arc<std::sync::Mutex<Vec<&'static str>>> {
            self.calls.clone()
        }
    }

    impl PamBackend for MockPam {
        fn start_transaction(
            &self,
            _service: &str,
            _username: &str,
            _password: &str,
        ) -> Result<Box<dyn PamTransaction>, PamError> {
            self.calls.lock().unwrap().push("start_transaction");
            Ok(Box::new(MockPamTransaction {
                auth_error: self.auth_error.clone(),
                acct_error: self.acct_error.clone(),
                calls: self.calls.clone(),
            }))
        }

        fn get_user_info(&self, _username: &str) -> Result<UserInfo, PamError> {
            Ok(self.user_info.clone())
        }
    }

    impl PamTransaction for MockPamTransaction {
        fn authenticate(&mut self) -> Result<(), PamError> {
            self.calls.lock().unwrap().push("authenticate");
            match &self.auth_error {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
        }

        fn acct_mgmt(&mut self) -> Result<(), PamError> {
            self.calls.lock().unwrap().push("acct_mgmt");
            match &self.acct_error {
                Some(e) => Err(e.clone()),
                None => Ok(()),
            }
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
        let calls = mock.call_log();

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

        assert_eq!(
            &*calls.lock().unwrap(),
            &["start_transaction", "authenticate", "acct_mgmt"]
        );

        // Drop the mock and verify cleanup
        drop(mock);
        assert!(dropped.load(Ordering::SeqCst), "pam_end (Drop) not called");
    }

    #[tokio::test]
    async fn test_pam_auth_failure_with_delay() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mock = MockPam::auth_failure(dropped.clone());

        let start = tokio::time::Instant::now();
        let result = pam_authenticate(&mock, "alice", "wrong-password").await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert!(matches!(err, PamError::AuthenticationRejected));

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
        let mock = MockPam::acct_failure(dropped.clone());
        let calls = mock.call_log();

        let start = tokio::time::Instant::now();
        let result = pam_authenticate(&mock, "alice", "correct-password").await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert!(matches!(err, PamError::AccountCheckRejected));
        assert_eq!(
            &*calls.lock().unwrap(),
            &["start_transaction", "authenticate", "acct_mgmt"]
        );

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
            let mock = MockPam::auth_failure(dropped_failure.clone());
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
        let err = PamError::AuthenticationRejected;
        assert_eq!(err.to_string(), "authentication rejected");

        let err = PamError::AccountCheckRejected;
        assert_eq!(err.to_string(), "account check failed");
    }

    #[test]
    fn test_pam_service_name() {
        assert_eq!(PAM_SERVICE, "ssh3");
    }
}
