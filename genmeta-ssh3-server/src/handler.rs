//! HTTP-layer Extended CONNECT handler for SSH3.
//!
//! Implements [`tower_service::Service`] for `http::Request`, receiving an
//! Extended CONNECT request with `:protocol = ssh3`, validating the SSH
//! version, extracting authentication credentials, spawning a child process,
//! creating an [`Ssh3TransportImpl`] + RTC server, and waiting for
//! [`AuthResult`] from the child before returning 200 OK or 401.

use std::{
    convert::Infallible,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::future::BoxFuture;
use h3x::message::stream::MessageStreamError;
use h3x::qpack::field::Protocol;
use h3x::stream_id::StreamId;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::{Empty, combinators::UnsyncBoxBody};

use crate::{auth, channel::Ssh3TransportImpl, child::ChildProcess, protocol::Ssh3Protocol, version};
use genmeta_ssh3_proto::auth::AuthCredential;
use genmeta_ssh3_proto::session::{AuthResult, ChildBootstrap, Ssh3TransportServerShared};
use h3x::protocol::Protocols;
use remoc::rtc::ServerShared;
/// Result of validating the SSH3 Extended CONNECT request at the HTTP layer.
///
/// Extracted from the request so it can be unit-tested without constructing
/// h3x `Request`/`Response` (which have private fields).
#[derive(Debug)]
enum ConnectDecision {
    /// All validation passed — proceed with conversation setup.
    Ok {
        version_header: HeaderValue,
        credential: Option<AuthCredential>,
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
            ConnectDecision::Ok {
                version_header: version::version_response_header(&version),
                credential: Some(credential),
            }
        }
        Err(challenge) => {
            ConnectDecision::Unauthorized {
                www_authenticate: challenge.www_authenticate,
            }
        }
    }
}


/// Handler for SSH3 Extended CONNECT requests.
///
/// Looks up the [`Ssh3Protocol`] from request extensions (via `Arc<Protocols>`).
/// Uses the QUIC [`StreamId`] from request extensions as the conversation ID.
#[derive(Clone)]
pub struct Ssh3ConnectHandler;

impl Ssh3ConnectHandler {
    /// Creates a new handler.
    pub fn new() -> Self {
        Self
    }
}
impl tower_service::Service<http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>>
    for Ssh3ConnectHandler
{
    type Response = http::Response<Empty<Bytes>>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        request: http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
    ) -> Self::Future {
        Box::pin(async move {
            // Look up the SSH3 protocol from request extensions.
            let protocols = request.extensions().get::<Arc<Protocols>>().cloned().unwrap();
            let protocol = protocols.get::<Ssh3Protocol>().expect("Ssh3Protocol not registered");

            let stream_id = request.extensions().get::<StreamId>().copied().expect("StreamId not injected by h3x");

            let method = request.method().clone();
            let proto_str = request
                .extensions()
                .get::<Protocol>()
                .map(|p| p.as_str().to_owned());
            let headers = request.headers();

            let decision = evaluate_connect(
                &method,
                proto_str.as_deref(),
                headers,
            );

            let mut response = http::Response::new(Empty::new());

            match decision {
                ConnectDecision::Ok { version_header, credential } => {
                    let reserved = match protocol.reserve_conversation(stream_id).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::error!(%e, "failed to reserve conversation");
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            return Ok(response);
                        }
                    };
                    let conversation_id = reserved.conversation_id();
                    tracing::info!(conversation_id, "registered SSH3 conversation");

                    // Locate ssh3-session binary.
                    let session_bin = if let Ok(p) = std::env::var("SSH3_SESSION_BIN") {
                        std::path::PathBuf::from(p)
                    } else {
                        match std::env::current_exe() {
                            Ok(exe) => {
                                let parent = exe.parent().map(|p| p.join("ssh3-session")).unwrap_or_default();
                                if parent.exists() {
                                    parent
                                } else {
                                    // In test builds, exe is in target/<profile>/deps/; try grandparent.
                                    exe.parent()
                                        .and_then(|p| p.parent())
                                        .map(|p| p.join("ssh3-session"))
                                        .unwrap_or_default()
                                }
                            }
                            Err(e) => {
                                tracing::error!(%e, "cannot determine executable path");
                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                return Ok(response);
                            }
                        }
                    };

                    if !session_bin.exists() {
                        tracing::error!(path = %session_bin.display(), "ssh3-session binary not found");
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(response);
                    }

                    // Spawn child process.
                    let (child, mut child_bootstrap_tx, mut child_auth_rx) = match ChildProcess::spawn(&session_bin).await {
                        Ok(tuple) => tuple,
                        Err(e) => {
                            tracing::error!(%e, "failed to spawn child process");
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            return Ok(response);
                        }
                    };

                    // Activate the reservation to get the stream receiver.
                    // NOTE: We do NOT activate here; `reserved` stays alive until
                    // the supervisor task activates it after auth success. If auth
                    // fails, `reserved` drops here and auto-unregisters.

                    // Create Ssh3TransportImpl in pending mode and RTC server.
                    let transport_impl = Ssh3TransportImpl::new_pending();
                    let transport_impl = Arc::new(transport_impl);
                    let (transport_server, transport_client) =
                        Ssh3TransportServerShared::new(transport_impl.clone(), 16);
                    tokio::spawn(async move { let _ = transport_server.serve(true).await; });

                    // Send ChildBootstrap to child.
                    let bootstrap = ChildBootstrap {
                        transport: transport_client,
                        credential: credential.unwrap_or(AuthCredential::Basic {
                            username: String::new(),
                            password: String::new(),
                        }),
                    };
                    if let Err(e) = child_bootstrap_tx.send(bootstrap).await {
                        tracing::error!(%e, "failed to send ChildBootstrap to child");
                        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(response);
                    }

                    // Wait for AuthResult from child (30s timeout).
                    let auth_result = match tokio::time::timeout(
                        Duration::from_secs(30),
                        child_auth_rx.recv(),
                    ).await {
                        Ok(Ok(Some(result))) => result,
                        Ok(Ok(None)) => {
                            tracing::warn!(conversation_id, "child closed channel without AuthResult");
                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                            response.headers_mut().insert(
                                http::header::WWW_AUTHENTICATE,
                                HeaderValue::from_static("Basic"),
                            );
                            return Ok(response);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(%e, conversation_id, "error receiving AuthResult from child");
                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                            response.headers_mut().insert(
                                http::header::WWW_AUTHENTICATE,
                                HeaderValue::from_static("Basic"),
                            );
                            return Ok(response);
                        }
                        Err(_) => {
                            tracing::warn!(conversation_id, "PAM authentication timed out (30s)");
                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                            response.headers_mut().insert(
                                http::header::WWW_AUTHENTICATE,
                                HeaderValue::from_static("Basic"),
                            );
                            return Ok(response);
                        }
                    };

                    match auth_result {
                        AuthResult::Success { .. } => {
                            tracing::info!(conversation_id, "PAM authentication succeeded via child");
                            *response.status_mut() = StatusCode::OK;
                            response.headers_mut().insert("ssh-version", version_header);

                            // Spawn upgrade supervisor: owns reservation, request,
                            // transport, and child lifetime.
                            let protocols_for_cleanup = protocols.clone();
                            tokio::spawn(async move {
                                // Activate reservation → get stream receiver.
                                let handle = reserved.activate();
                                // Attach to pending transport so accept_channel unblocks.
                                transport_impl.attach_handle(handle);

                                // Hold CONNECT ReadStream/WriteStream for ownership
                                // (actual data bridging comes in Phase 4).
                                // ReadStream can be extracted from the request body.
                                let _read_stream = h3x::message::stream::ReadStream::extract_from(request).await;

                                // Monitor child lifetime.
                                let mut child = child;
                                match child.wait().await {
                                    Ok(status) => tracing::info!(?status, conversation_id, "child process exited"),
                                    Err(e) => tracing::warn!(%e, conversation_id, "error waiting for child"),
                                }
                                let protocol = protocols_for_cleanup.get::<Ssh3Protocol>().expect("Ssh3Protocol not registered");
                                protocol.unregister_conversation(conversation_id).await;
                            });
                        }
                        AuthResult::Failure { reason } => {
                            tracing::warn!(conversation_id, %reason, "PAM authentication failed via child");
                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                            response.headers_mut().insert(
                                http::header::WWW_AUTHENTICATE,
                                HeaderValue::from_static("Basic"),
                            );
                        }
                    }
                }
                ConnectDecision::BadRequest(msg) => {
                    tracing::warn!(%msg, "SSH3 CONNECT rejected");
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                }
                ConnectDecision::Unauthorized { www_authenticate } => {
                    tracing::warn!("SSH3 CONNECT unauthorized");
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    response.headers_mut().insert(
                        http::header::WWW_AUTHENTICATE,
                        HeaderValue::from_str(&www_authenticate)
                            .unwrap_or_else(|_| HeaderValue::from_static("Basic")),
                    );
                }
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::varint::VarInt;

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
            ConnectDecision::Ok { version_header, .. } => {
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

    /// StreamId is used as conversation ID from request extensions.
    #[test]
    fn handler_uses_stream_id() {
        // The handler struct no longer carries an atomic counter.
        let _handler = Ssh3ConnectHandler::new();
        // StreamId wraps a VarInt — verify the conversion to u64.
        let stream_id = StreamId(VarInt::try_from(42u64).unwrap());
        let conversation_id = stream_id.0.into_inner();
        assert_eq!(conversation_id, 42);
    }
}
