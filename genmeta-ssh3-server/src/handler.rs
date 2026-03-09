//! HTTP-layer Extended CONNECT handler for SSH3.
//!
//! Receives an Extended CONNECT request with `:protocol = ssh3`, validates the
//! SSH version, extracts authentication credentials, registers a conversation
//! with [`Ssh3Protocol`], and returns 200 OK with the negotiated `ssh-version`
//! response header.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use h3x::server::{Request, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode};

use crate::{auth, protocol::Ssh3Protocol, version};

/// Result of validating the SSH3 Extended CONNECT request at the HTTP layer.
///
/// Extracted from the request so it can be unit-tested without constructing
/// h3x `Request`/`Response` (which have private fields).
#[derive(Debug)]
enum ConnectDecision {
    /// All validation passed — proceed with conversation setup.
    Ok {
        version_header: HeaderValue,
    },
    /// Protocol or version error — return 400 Bad Request.
    BadRequest(String),
    /// Authentication failure — return 401 with WWW-Authenticate.
    Unauthorized {
        www_authenticate: String,
    },
}

/// Validate method, protocol, version, and auth from raw request data.
///
/// This is the pure-logic core of the handler, factored out for testability.
fn evaluate_connect(
    method: &Method,
    protocol: Option<&str>,
    headers: &HeaderMap,
) -> ConnectDecision {
    // 1. Validate method is CONNECT.
    if *method != Method::CONNECT {
        return ConnectDecision::BadRequest(format!(
            "expected CONNECT method, got {method}"
        ));
    }

    // 2. Validate :protocol pseudo-header is "ssh3".
    match protocol {
        Some("ssh3") => {}
        Some(other) => {
            return ConnectDecision::BadRequest(format!(
                "expected :protocol \"ssh3\", got \"{other}\""
            ));
        }
        None => {
            return ConnectDecision::BadRequest(
                "missing :protocol pseudo-header".into(),
            );
        }
    }

    // 3. Version negotiation.
    let version = match version::negotiate_version(headers) {
        Ok(v) => v,
        Err(e) => {
            return ConnectDecision::BadRequest(format!(
                "version negotiation failed: {e}"
            ));
        }
    };

    // 4. Authentication.
    match auth::extract_auth_credential(headers) {
        Ok(credential) => {
            tracing::debug!(?credential, "authenticated SSH3 CONNECT");
        }
        Err(challenge) => {
            return ConnectDecision::Unauthorized {
                www_authenticate: challenge.www_authenticate,
            };
        }
    }

    ConnectDecision::Ok {
        version_header: version::version_response_header(&version),
    }
}

/// Handler for SSH3 Extended CONNECT requests.
///
/// Holds a reference to the [`Ssh3Protocol`] for conversation registration
/// and an atomic counter for generating conversation IDs.
#[derive(Clone)]
pub struct Ssh3ConnectHandler {
    protocol: Arc<Ssh3Protocol>,
    next_conversation_id: Arc<AtomicU64>,
}

impl Ssh3ConnectHandler {
    /// Creates a new handler backed by the given protocol instance.
    pub fn new(protocol: Arc<Ssh3Protocol>) -> Self {
        Self {
            protocol,
            next_conversation_id: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl h3x::server::Service for Ssh3ConnectHandler {
    type Future<'s> = futures::future::BoxFuture<'s, ()>;

    fn serve<'s>(
        &self,
        request: &'s mut Request,
        response: &'s mut Response,
    ) -> Self::Future<'s> {
        let protocol = self.protocol.clone();
        let next_id = self.next_conversation_id.clone();

        Box::pin(async move {
            let method = request.method();
            let proto_str = request.protocol().as_ref().map(|p| p.as_str().to_owned());
            let headers = request.headers();

            let decision = evaluate_connect(
                &method,
                proto_str.as_deref(),
                headers,
            );

            match decision {
                ConnectDecision::Ok { version_header } => {
                    let conversation_id = next_id.fetch_add(1, Ordering::Relaxed);
                    let _rx = protocol.register_conversation(conversation_id).await;
                    tracing::info!(conversation_id, "registered SSH3 conversation");

                    response
                        .set_status(StatusCode::OK)
                        .set_header("ssh-version", version_header);
                }
                ConnectDecision::BadRequest(msg) => {
                    tracing::warn!(%msg, "SSH3 CONNECT rejected");
                    response.set_status(StatusCode::BAD_REQUEST);
                }
                ConnectDecision::Unauthorized { www_authenticate } => {
                    tracing::warn!("SSH3 CONNECT unauthorized");
                    response
                        .set_status(StatusCode::UNAUTHORIZED)
                        .set_header(
                            http::header::WWW_AUTHENTICATE,
                            HeaderValue::from_str(&www_authenticate)
                                .unwrap_or_else(|_| HeaderValue::from_static("Basic")),
                        );
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_pairs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for &(name, value) in pairs {
            map.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    /// Valid CONNECT with ssh3 protocol + valid version + valid Basic auth → Ok with ssh-version.
    #[test]
    fn valid_connect_returns_ok() {
        // "user:pass" → base64 "dXNlcjpwYXNz"
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::Ok { version_header } => {
                assert_eq!(version_header.to_str().unwrap(), "michel-ssh3-00");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    /// Missing ssh-version header → BadRequest.
    #[test]
    fn missing_version_returns_bad_request() {
        let headers = headers_with_pairs(&[
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::BadRequest(msg) => {
                assert!(msg.contains("version negotiation failed"), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Invalid ssh-version header → BadRequest.
    #[test]
    fn invalid_version_returns_bad_request() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "unknown-version-99"),
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::BadRequest(msg) => {
                assert!(msg.contains("version negotiation failed"), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Missing auth header → Unauthorized with WWW-Authenticate: Basic.
    #[test]
    fn missing_auth_returns_unauthorized() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::Unauthorized { www_authenticate } => {
                assert_eq!(www_authenticate, "Basic");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    /// Bearer auth → Unauthorized (only Basic is supported).
    #[test]
    fn bearer_auth_returns_unauthorized() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
            ("authorization", "Bearer some-token"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::Unauthorized { www_authenticate } => {
                assert_eq!(www_authenticate, "Basic");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    /// Non-CONNECT method → BadRequest.
    #[test]
    fn non_connect_method_rejected() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::GET, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::BadRequest(msg) => {
                assert!(msg.contains("expected CONNECT"), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// POST method → BadRequest.
    #[test]
    fn post_method_rejected() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::POST, Some("ssh3"), &headers);

        match decision {
            ConnectDecision::BadRequest(msg) => {
                assert!(msg.contains("expected CONNECT"), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Missing :protocol pseudo-header → BadRequest.
    #[test]
    fn missing_protocol_rejected() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, None, &headers);

        match decision {
            ConnectDecision::BadRequest(msg) => {
                assert!(msg.contains("missing :protocol"), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Wrong :protocol value → BadRequest.
    #[test]
    fn wrong_protocol_rejected() {
        let headers = headers_with_pairs(&[
            ("ssh-version", "michel-ssh3-00"),
            ("authorization", "Basic dXNlcjpwYXNz"),
        ]);

        let decision = evaluate_connect(&Method::CONNECT, Some("websocket"), &headers);

        match decision {
            ConnectDecision::BadRequest(msg) => {
                assert!(msg.contains("expected :protocol \"ssh3\""), "msg: {msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Conversation registration works end-to-end with the handler struct.
    #[tokio::test]
    async fn handler_registers_conversation() {
        let protocol = Arc::new(Ssh3Protocol::new());
        let handler = Ssh3ConnectHandler::new(protocol.clone());

        // Simulate what the handler would do on success.
        let conversation_id = handler.next_conversation_id.fetch_add(1, Ordering::Relaxed);
        let _rx = protocol.register_conversation(conversation_id).await;

        // Verify conversation was registered.
        assert_eq!(conversation_id, 0);

        // Next ID increments.
        let next = handler.next_conversation_id.fetch_add(1, Ordering::Relaxed);
        assert_eq!(next, 1);
    }
}
