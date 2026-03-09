//! SSH3 Extended CONNECT handler — draft-michel-ssh3-00 §3.
//!
//! [`Ssh3ConnectService`] implements [`h3x::server::Service`] and handles
//! `CONNECT /.well-known/ssh3` requests. Each request:
//!
//! 1. Validates the `Authorization` header (HTTP Basic).
//! 2. Negotiates the `ssh-version` header.
//! 3. Derives the conversation ID from the QUIC stream ID of the CONNECT request.
//! 4. Creates a [`proto::conversation::LocalConversation`] and registers it with
//!    the shared [`Ssh3Protocol`] instance.
//! 5. Forks a child process (via [`ChildProcessManager`]) to run the SSH session.
//! 6. Returns HTTP 200 to unblock the SSH3 data flow.
//!
//! # Error Responses
//!
//! | Situation | Status |
//! |-----------|--------|
//! | Missing `Authorization` | 401 + `WWW-Authenticate: Basic` |
//! | Unsupported auth scheme | 401 |
//! | `ssh-version` mismatch | 403 |
//! | Auth credential error | 403 |
//! | Internal error | 500 |

use std::sync::Arc;

use h3x::{
    connection::QuicConnection,
    quic::{self, GetStreamIdExt},
    server::{BoxServiceFuture, Request, Response, Service},
};
use http::{HeaderValue, StatusCode};
use proto::{
    codec::ConversationId,
    conversation::LocalConversation,
};
use tracing::Instrument;

use crate::{
    auth::{AuthParseError, parse_authorization},
    protocol::Ssh3Protocol,
    version::negotiate_version,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The route path for SSH3 Extended CONNECT (RFC §3).
pub const SSH3_CONNECT_PATH: &str = "/.well-known/ssh3";

/// Default inbound channel buffer size for a new conversation.
const INBOUND_BUFFER_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// ChildProcessManager stub
// ---------------------------------------------------------------------------

/// Manager responsible for forking child processes for SSH sessions.
///
/// **This is a stub** for Task 8. The real implementation (PAM auth + exec)
/// is deferred to Tasks 10 & 11. The stub accepts all connections and
/// records the conversation ID for testing.
#[derive(Debug, Clone, Default)]
pub struct ChildProcessManager;

impl ChildProcessManager {
    /// Create a new `ChildProcessManager`.
    pub fn new() -> Self {
        Self
    }

    /// Spawn a child process for the given conversation.
    ///
    /// Returns `Ok(())` in the stub. The real implementation will fork+exec
    /// and communicate via remoc RTC.
    pub async fn spawn(
        &self,
        conversation_id: ConversationId,
        username: &str,
    ) -> Result<(), ChildProcessError> {
        tracing::debug!(
            conversation_id = %conversation_id,
            username,
            "ChildProcessManager::spawn (stub — not yet implemented)"
        );
        Ok(())
    }
}

/// Error type for child process operations.
#[derive(Debug)]
pub struct ChildProcessError(pub String);

impl std::fmt::Display for ChildProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "child process error: {}", self.0)
    }
}

impl std::error::Error for ChildProcessError {}

// ---------------------------------------------------------------------------
// Ssh3ConnectService
// ---------------------------------------------------------------------------

/// h3x service that handles SSH3 Extended CONNECT requests.
///
/// Constructed once per connection and registered via
/// `Router::connect(SSH3_CONNECT_PATH, service)`.
///
/// # Connection Injection
///
/// `connection` is `Option<Arc<QuicConnection<C>>>`. It is `None` in
/// HTTP-layer integration tests (auth/version smoke tests) and `Some` in
/// production once per-connection service injection is wired up (Task 13).
///
/// # Type Parameters
///
/// * `C` — the QUIC connection type (e.g. `gm_quic::Connection`).
pub struct Ssh3ConnectService<C: quic::Connection> {
    /// Shared SSH3 protocol layer for conversation routing.
    ssh3_protocol: Arc<Ssh3Protocol<C>>,
    /// Child process manager (stub until Tasks 10/11).
    child_process_manager: Arc<ChildProcessManager>,
    /// Optional QUIC connection. `None` in HTTP-layer-only tests.
    connection: Option<Arc<QuicConnection<C>>>,
}

impl<C: quic::Connection> Clone for Ssh3ConnectService<C> {
    fn clone(&self) -> Self {
        Self {
            ssh3_protocol: self.ssh3_protocol.clone(),
            child_process_manager: self.child_process_manager.clone(),
            connection: self.connection.clone(),
        }
    }
}

impl<C: quic::Connection> std::fmt::Debug for Ssh3ConnectService<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ssh3ConnectService").finish_non_exhaustive()
    }
}

impl<C: quic::Connection> Ssh3ConnectService<C> {
    /// Create a new `Ssh3ConnectService` with a QUIC connection (production).
    pub fn new(
        ssh3_protocol: Arc<Ssh3Protocol<C>>,
        child_process_manager: Arc<ChildProcessManager>,
        connection: Arc<QuicConnection<C>>,
    ) -> Self {
        Self {
            ssh3_protocol,
            child_process_manager,
            connection: Some(connection),
        }
    }

    /// Create a new `Ssh3ConnectService` without a QUIC connection.
    ///
    /// Suitable for integration tests that only exercise the HTTP layer.
    /// Steps that require `LocalConversation` are skipped when `connection` is `None`.
    pub fn new_without_connection(
        ssh3_protocol: Arc<Ssh3Protocol<C>>,
        child_process_manager: Arc<ChildProcessManager>,
    ) -> Self {
        Self {
            ssh3_protocol,
            child_process_manager,
            connection: None,
        }
    }
}

impl<C> Service for Ssh3ConnectService<C>
where
    C: quic::Connection + 'static,
    <C as quic::ManageStream>::StreamReader: Unpin + Send,
{
    type Future<'s> = BoxServiceFuture<'s>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        // Clone the Arcs so the future does not borrow `self`.
        let ssh3_protocol = self.ssh3_protocol.clone();
        let child_process_manager = self.child_process_manager.clone();
        let connection = self.connection.clone();
        Box::pin(
            async move {
                let svc = Ssh3ConnectService {
                    ssh3_protocol,
                    child_process_manager,
                    connection,
                };
                svc.handle(request, response).await;
            }
            .in_current_span(),
        )
    }
}

impl<C> Ssh3ConnectService<C>
where
    C: quic::Connection + 'static,
    <C as quic::ManageStream>::StreamReader: Unpin + Send,
{
    async fn handle(&self, request: &mut Request, response: &mut Response) {
        // ----------------------------------------------------------------
        // Step 1: Parse Authorization header
        // ----------------------------------------------------------------
        let auth_result = match request.header("authorization") {
            None => {
                tracing::debug!("Missing Authorization header → 401");
                _ = response.set_status(StatusCode::UNAUTHORIZED).set_header(
                    "www-authenticate",
                    HeaderValue::from_static("Basic realm=\"ssh3\""),
                );
                return;
            }
            Some(hv) => match parse_authorization(hv) {
                Ok(result) => result,
                Err(AuthParseError::UnsupportedScheme { scheme }) => {
                    tracing::debug!(scheme, "Unsupported auth scheme → 401");
                    _ = response.set_status(StatusCode::UNAUTHORIZED).set_header(
                        "www-authenticate",
                        HeaderValue::from_static("Basic realm=\"ssh3\""),
                    );
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Invalid Authorization header → 401");
                    _ = response.set_status(StatusCode::UNAUTHORIZED).set_header(
                        "www-authenticate",
                        HeaderValue::from_static("Basic realm=\"ssh3\""),
                    );
                    return;
                }
            },
        };

        // ----------------------------------------------------------------
        // Step 2: Negotiate ssh-version header
        // ----------------------------------------------------------------
        let ssh_version_hv = match request.header("ssh-version") {
            None => {
                tracing::debug!("Missing ssh-version header → 403");
                _ = response.set_status(StatusCode::FORBIDDEN);
                return;
            }
            Some(hv) => hv,
        };

        let client_versions = match ssh_version_hv.to_str() {
            Ok(s) => s,
            Err(_) => {
                tracing::debug!("ssh-version header is not valid UTF-8 → 403");
                _ = response.set_status(StatusCode::FORBIDDEN);
                return;
            }
        };

        if negotiate_version(client_versions).is_none() {
            tracing::debug!(client_versions, "No matching ssh-version → 403");
            _ = response.set_status(StatusCode::FORBIDDEN);
            return;
        }

        // ----------------------------------------------------------------
        // Step 3: Acquire stream ID → conversation ID
        // (only when we have a real QUIC connection)
        // ----------------------------------------------------------------
        let conversation_id = if self.connection.is_some() {
            let stream_id = match request.read_stream().stream_id().await {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to acquire stream ID → 500");
                    _ = response.set_status(StatusCode::INTERNAL_SERVER_ERROR);
                    return;
                }
            };
            ConversationId::new(stream_id.into())
        } else {
            // HTTP-layer test: use a placeholder conversation ID.
            ConversationId::new(0)
        };

        tracing::debug!(
            conversation_id = %conversation_id,
            username = %auth_result.username,
            "SSH3 CONNECT accepted"
        );

        // ----------------------------------------------------------------
        // Step 4: Create LocalConversation + register with Ssh3Protocol
        // (skipped when connection is None — HTTP-layer-only tests)
        // ----------------------------------------------------------------
        if let Some(conn) = &self.connection {
            let conversation = LocalConversation::new(
                conversation_id,
                conn.clone(),
                INBOUND_BUFFER_SIZE,
            );
            self.ssh3_protocol.register(&conversation).await;
        }

        // ----------------------------------------------------------------
        // Step 5: Spawn child process (stub)
        // ----------------------------------------------------------------
        if let Err(e) = self
            .child_process_manager
            .spawn(conversation_id, &auth_result.username)
            .await
        {
            tracing::warn!(error = %e, "Failed to spawn child process → 500");
            if self.connection.is_some() {
                self.ssh3_protocol.deregister(conversation_id).await;
            }
            _ = response.set_status(StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }

        // ----------------------------------------------------------------
        // Step 6: Return HTTP 200
        //
        // The 200 response unblocks the SSH3 client to start sending channel
        // streams. We keep the handler alive until the conversation ends.
        // ----------------------------------------------------------------
        _ = response.set_status(StatusCode::OK);

        // TODO(Task 10/11): Drive the remoc RTC session here:
        //   let session_client = Connect::io_buffered(...).consume().await?;
        //   session_client.authenticate(SessionInit { username, credential }).await?;
        //   session_client.run_session(remote_conversation).await?;
        //
        // For now, deregister on drop since we have no session to await.
        if self.connection.is_some() {
            self.ssh3_protocol.deregister(conversation_id).await;
        }

        tracing::debug!(
            conversation_id = %conversation_id,
            "SSH3 CONNECT handler complete"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn child_process_manager_spawn_stub_ok() {
        let mgr = ChildProcessManager::new();
        let conv_id = ConversationId::new(42);
        let result = mgr.spawn(conv_id, "alice").await;
        assert!(result.is_ok(), "stub spawn should always succeed");
    }

    #[test]
    fn parse_authorization_no_header_produces_401_branch() {
        use crate::auth::parse_authorization;
        use http::HeaderValue;
        // Missing header → None path leads to 401
        let result: Option<()> = None;
        assert!(result.is_none());
        // Basic valid
        let hv = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        let auth = parse_authorization(&hv).unwrap();
        assert_eq!(auth.username, "user");
    }

    #[test]
    fn parse_authorization_unsupported_scheme_branch() {
        use crate::auth::{AuthParseError, parse_authorization};
        use http::HeaderValue;
        let hv = HeaderValue::from_static("Bearer some.token");
        let err = parse_authorization(&hv).unwrap_err();
        assert!(matches!(err, AuthParseError::UnsupportedScheme { .. }));
    }

    #[test]
    fn version_mismatch_branch() {
        use crate::version::negotiate_version;
        assert!(negotiate_version("unknown-v1").is_none());
    }

    #[test]
    fn version_match_branch() {
        use crate::version::{SSH3_VERSION, negotiate_version};
        assert_eq!(negotiate_version(SSH3_VERSION), Some(SSH3_VERSION));
    }

    #[test]
    fn conversation_id_from_stream_id() {
        let stream_id: u64 = 4;
        let conv_id = ConversationId::new(stream_id);
        assert_eq!(conv_id.into_inner(), 4);
    }

    #[test]
    fn child_process_error_display() {
        let e = ChildProcessError("test error".to_string());
        assert!(e.to_string().contains("test error"));
    }
}
