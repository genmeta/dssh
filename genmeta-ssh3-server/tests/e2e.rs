//! E2E smoke tests for the SSH3 server — Task 9.
//!
//! These tests exercise the HTTP-level authentication and version negotiation
//! at the server's Extended CONNECT endpoint:
//!
//! 1. `connect_auth_exec_smoke`   — valid Basic auth + correct ssh-version → HTTP 200
//! 2. `connect_wrong_version`     — valid auth + wrong ssh-version → HTTP 403
//! 3. `connect_no_auth`           — missing Authorization header → HTTP 401
//!
//! The tests use plain async fn handlers (not `Ssh3ConnectService<C>`) because
//! the full service requires a per-connection `Arc<QuicConnection<C>>` that is
//! not yet plumbed through the `Router` at construction time. The handler below
//! replicates the relevant logic using the same helper functions.

mod common;
use common::*;

use genmeta_ssh3_server::{
    auth::{AuthParseError, parse_authorization},
    handler::SSH3_CONNECT_PATH,
    version::{SSH3_VERSION, negotiate_version},
};
use h3x::{
    qpack::field::Protocol,
    server::{self, Router},
};
use http::{HeaderValue, Method, StatusCode, uri::Scheme};
use tokio_util::task::AbortOnDropHandle;

// ---------------------------------------------------------------------------
// Test handler — replicates Ssh3ConnectService logic without QuicConnection
// ---------------------------------------------------------------------------

/// Minimal SSH3 CONNECT handler for E2E testing.
///
/// Validates auth and version exactly as `Ssh3ConnectService::handle` does,
/// then returns 200 on success. Skips steps 3-6 (stream-ID, conversation,
/// child process) since those require a live QUIC connection.
async fn ssh3_connect_handler(request: &mut server::Request, response: &mut server::Response) {
    // Step 1: Authorization header
    let auth_result = match request.header("authorization") {
        None => {
            _ = response.set_status(StatusCode::UNAUTHORIZED).set_header(
                "www-authenticate",
                HeaderValue::from_static("Basic realm=\"ssh3\""),
            );
            return;
        }
        Some(hv) => match parse_authorization(hv) {
            Ok(result) => result,
            Err(AuthParseError::UnsupportedScheme { .. }) | Err(_) => {
                _ = response.set_status(StatusCode::UNAUTHORIZED).set_header(
                    "www-authenticate",
                    HeaderValue::from_static("Basic realm=\"ssh3\""),
                );
                return;
            }
        },
    };

    // Step 2: ssh-version header
    let ssh_version_hv = match request.header("ssh-version") {
        None => {
            _ = response.set_status(StatusCode::FORBIDDEN);
            return;
        }
        Some(hv) => hv,
    };

    let client_versions = match ssh_version_hv.to_str() {
        Ok(s) => s,
        Err(_) => {
            _ = response.set_status(StatusCode::FORBIDDEN);
            return;
        }
    };

    if negotiate_version(client_versions).is_none() {
        _ = response.set_status(StatusCode::FORBIDDEN);
        return;
    }

    tracing::debug!(username = %auth_result.username, "SSH3 CONNECT test handler accepted");
    _ = response.set_status(StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Helper: build an h3x Router with our test handler at the SSH3 CONNECT path.
fn make_router() -> Router {
    Router::new().connect(SSH3_CONNECT_PATH, ssh3_connect_handler)
}

/// Test 1: Valid Basic auth + correct ssh-version → HTTP 200.
#[test]
fn connect_auth_exec_smoke() {
    run("connect_auth_exec_smoke", async move {
        let server = test_server(make_router()).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        // "user:pass" in Base64 = "dXNlcjpwYXNz"
        let (_, response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_scheme(Scheme::HTTPS)
            .with_protocol(Protocol::new("ssh3"))
            .with_authority(authority)
            .with_path(SSH3_CONNECT_PATH.parse().expect("valid path"))
            .with_header(
                "authorization",
                HeaderValue::from_static("Basic dXNlcjpwYXNz"),
            )
            .with_header(
                "ssh-version",
                HeaderValue::from_str(SSH3_VERSION).expect("valid header value"),
            )
            .execute()
            .await
            .expect("request failed");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "expected 200 for valid auth + correct version"
        );
    })
}

/// Test 2: Valid auth + wrong/unsupported ssh-version → HTTP 403.
#[test]
fn connect_wrong_version() {
    run("connect_wrong_version", async move {
        let server = test_server(make_router()).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        let (_, response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_scheme(Scheme::HTTPS)
            .with_protocol(Protocol::new("ssh3"))
            .with_authority(authority)
            .with_path(SSH3_CONNECT_PATH.parse().expect("valid path"))
            .with_header(
                "authorization",
                HeaderValue::from_static("Basic dXNlcjpwYXNz"),
            )
            .with_header("ssh-version", HeaderValue::from_static("unknown-v999"))
            .execute()
            .await
            .expect("request failed");

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "expected 403 for unknown ssh-version"
        );
    })
}

/// Test 3: Missing Authorization header → HTTP 401.
#[test]
fn connect_no_auth() {
    run("connect_no_auth", async move {
        let server = test_server(make_router()).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        let (_, response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_scheme(Scheme::HTTPS)
            .with_protocol(Protocol::new("ssh3"))
            .with_authority(authority)
            .with_path(SSH3_CONNECT_PATH.parse().expect("valid path"))
            .with_header(
                "ssh-version",
                HeaderValue::from_str(SSH3_VERSION).expect("valid header value"),
            )
            // intentionally omit Authorization
            .execute()
            .await
            .expect("request failed");

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 when Authorization header is missing"
        );
    })
}
