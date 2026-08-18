//! PAM authentication for privilege-separated child processes.
//!
//! Performs non-interactive PAM authentication using `pam-client2` and
//! looks up the user in `/etc/passwd` via `nix::unistd::User`.
//!
//! PAM is a synchronous C library. Session-opening calls are intentionally
//! executed on the thread polling the returned future because Linux
//! `pam_loginuid` requires the process leader thread.

use snafu::{OptionExt, ResultExt, Snafu};

pub use super::UserInfo;

/// Errors that can occur during PAM authentication or user lookup.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PamAuthError {
    /// Failed to initialize the PAM context.
    #[snafu(display("failed to create PAM context"))]
    CreateContext { source: pam_client2::Error },

    /// `pam_authenticate` rejected the credentials.
    #[snafu(display("PAM authentication rejected"))]
    Authenticate { source: pam_client2::Error },

    /// `pam_acct_mgmt` rejected the account (expired, locked, etc.).
    #[snafu(display("PAM account management rejected"))]
    AccountManagement { source: pam_client2::Error },

    /// `pam_open_session` failed.
    #[snafu(display("PAM open_session failed"))]
    OpenSession { source: pam_client2::Error },

    /// Failed to query `/etc/passwd` for the user.
    #[snafu(display("failed to query user from /etc/passwd"))]
    UserQuery { source: nix::Error },

    /// The username does not exist in `/etc/passwd`.
    #[snafu(display("user not found in /etc/passwd: {username}"))]
    UserNotFound { username: String },

    /// Linux `pam_loginuid` requires PAM session setup on the process leader.
    #[cfg(target_os = "linux")]
    #[snafu(display(
        "PAM session setup must run on the process leader thread (pid={pid}, tid={tid})"
    ))]
    ProcessLeaderRequired { pid: i32, tid: i32 },
}

/// Perform PAM authentication and look up the user's POSIX identity.
///
/// This function:
/// 1. Creates a non-interactive PAM context with `conv_mock::Conversation`
/// 2. Calls `pam_authenticate` to verify the password
/// 3. Calls `pam_acct_mgmt` to check account status (expired, locked, etc.)
/// 4. Looks up the user in `/etc/passwd` via `nix::unistd::User::from_name`
///
/// This future performs synchronous PAM work on the thread that polls it.
/// On Linux, the caller must ensure that thread is the process leader because
/// `pam_loginuid` writes `/proc/self/loginuid` during `pam_open_session`.
pub async fn authenticate(
    service: &str,
    username: &str,
    password: &str,
) -> Result<UserInfo, PamAuthError> {
    authenticate_blocking(service, username, password)
}

fn authenticate_blocking(
    service: &str,
    username: &str,
    password: &str,
) -> Result<UserInfo, PamAuthError> {
    use pam_client2::{Context, Flag, conv_mock};

    ensure_process_leader()?;

    let conversation = conv_mock::Conversation::with_credentials(username, password);
    let mut context = Context::new(service, Some(username), conversation)
        .context(pam_auth_error::CreateContextSnafu)?;

    // Set PAM_TTY so that pam_systemd registers a logind session.
    // OpenSSH sets this to "ssh" before PTY allocation.
    let _ = context.set_tty(Some("ssh"));

    context
        .authenticate(Flag::NONE)
        .context(pam_auth_error::AuthenticateSnafu)?;

    context
        .acct_mgmt(Flag::NONE)
        .context(pam_auth_error::AccountManagementSnafu)?;

    // Open a PAM session so that pam_lastlog, pam_umask, pam_env etc. run.
    let session = context
        .open_session(Flag::NONE)
        .context(pam_auth_error::OpenSessionSnafu)?;

    // Extract PAM environment from the session while it borrows context.
    let pam_env = extract_pam_env(&session);

    // Leak both — close_session requires root, which we drop later.
    let _ = session.leak();
    std::mem::forget(context);

    let user = nix::unistd::User::from_name(username)
        .context(pam_auth_error::UserQuerySnafu)?
        .context(pam_auth_error::UserNotFoundSnafu { username })?;

    Ok(UserInfo {
        username: user.name,
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
        home: user.dir,
        shell: user.shell,
        pam_env,
    })
}

/// PAM account check and session open **without** password authentication.
///
/// Used for mTLS certificate-based logins where the transport layer has
/// already verified the client's identity. This function:
/// 1. Creates a PAM context with a no-op conversation (no password)
/// 2. Calls `pam_acct_mgmt` to verify the account is valid
/// 3. Calls `pam_open_session` to create a system session
/// 4. Looks up the user in `/etc/passwd`
///
/// The returned PAM context is intentionally leaked because
/// `pam_close_session` requires root privileges, which are dropped before
/// the session ends.
///
/// This future performs synchronous PAM work on the thread that polls it.
/// On Linux, the caller must ensure that thread is the process leader because
/// `pam_loginuid` writes `/proc/self/loginuid` during `pam_open_session`.
pub async fn open_session(service: &str, username: &str) -> Result<UserInfo, PamAuthError> {
    open_session_blocking(service, username)
}

fn open_session_blocking(service: &str, username: &str) -> Result<UserInfo, PamAuthError> {
    use pam_client2::{Context, Flag, conv_null};

    ensure_process_leader()?;

    let conversation = conv_null::Conversation::new();
    let mut context = Context::new(service, Some(username), conversation)
        .context(pam_auth_error::CreateContextSnafu)?;

    // Set PAM_TTY so that pam_systemd registers a logind session.
    // OpenSSH sets this to "ssh" before PTY allocation.
    let _ = context.set_tty(Some("ssh"));

    context
        .acct_mgmt(Flag::NONE)
        .context(pam_auth_error::AccountManagementSnafu)?;

    let session = context
        .open_session(Flag::NONE)
        .context(pam_auth_error::OpenSessionSnafu)?;

    // Extract PAM environment from the session while it borrows context.
    let pam_env = extract_pam_env(&session);

    // Leak both — close_session requires root, which we drop later.
    let _ = session.leak();
    std::mem::forget(context);

    let user = nix::unistd::User::from_name(username)
        .context(pam_auth_error::UserQuerySnafu)?
        .context(pam_auth_error::UserNotFoundSnafu { username })?;

    Ok(UserInfo {
        username: user.name,
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
        home: user.dir,
        shell: user.shell,
        pam_env,
    })
}

#[cfg(target_os = "linux")]
fn ensure_process_leader() -> Result<(), PamAuthError> {
    let pid = nix::unistd::getpid().as_raw();
    let tid = nix::unistd::gettid().as_raw();

    if pid == tid {
        Ok(())
    } else {
        Err(PamAuthError::ProcessLeaderRequired { pid, tid })
    }
}

#[cfg(not(target_os = "linux"))]
fn ensure_process_leader() -> Result<(), PamAuthError> {
    Ok(())
}

/// Extract PAM environment variables as `Vec<(String, String)>`.
///
/// Calls `pam_getenvlist()` via the session handle and collects `KEY=VALUE`
/// pairs, skipping entries that are not valid UTF-8.
fn extract_pam_env<C: pam_client2::ConversationHandler>(
    session: &pam_client2::Session<'_, C>,
) -> Vec<(String, String)> {
    session
        .envlist()
        .iter_tuples()
        .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v.to_str()?.to_owned())))
        .collect()
}
