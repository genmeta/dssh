//! HTTP-layer Extended CONNECT handler for SSH3.
//!
//! Implements [`tower_service::Service`] for `http::Request`, receiving an
//! Extended CONNECT request with `:protocol = ssh3`, validating the SSH
//! version, extracting authentication credentials, spawning a child process,
//! creating an SSH3 transport server, and waiting for
//! [`AuthResult`] from the child before returning 200 OK or 401.

use std::{
    convert::Infallible,
    io,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
use h3x::qpack::field::Protocol;
use h3x::stream_id::StreamId;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::Empty;
use snafu::Report;
use tracing::Instrument;

use crate::{auth, child::ChildProcess, error::ServerError, protocol::Ssh3Protocol, version};
use crate::channel::{GlobalRequestContext, serve_control_stream_global_requests};
use crate::forward::reverse_tcp::ReverseTcpForwarder;
use crate::forward::streamlocal::ReverseStreamlocalForwarder;
use genmeta_ssh3_proto::auth::AuthCredential;
use genmeta_ssh3_proto::session::{AuthResult, ChildBootstrap};
use h3x::hyper::upgrade;
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
            tracing::debug!(%credential, "authenticated SSH3 CONNECT");
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

    async fn handle_request<B>(
        &self,
        request: http::Request<B>,
    ) -> http::Response<Empty<bytes::Bytes>>
    where
        B: http_body::Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Send,
    {
        let Some(protocols) = request.extensions().get::<Arc<Protocols>>().cloned() else {
            tracing::error!(error = %Report::from_error(ServerError::MissingProtocols), "failed to handle SSH3 CONNECT");
            return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(protocol) = protocols.get::<Ssh3Protocol>() else {
            tracing::error!(error = %Report::from_error(ServerError::MissingSsh3Protocol), "failed to handle SSH3 CONNECT");
            return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let Some(stream_id) = request.extensions().get::<StreamId>().copied() else {
            tracing::error!(error = %Report::from_error(ServerError::MissingStreamId), "failed to handle SSH3 CONNECT");
            return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        };

        let method = request.method().clone();
        let proto_str = request
            .extensions()
            .get::<Protocol>()
            .map(|p| p.as_str().to_owned());
        let decision = evaluate_connect(&method, proto_str.as_deref(), request.headers());

        match decision {
            ConnectDecision::Ok { version_header, credential } => {
                self.handle_accepted_connect(request, protocol, stream_id, version_header, credential)
                    .await
            }
            ConnectDecision::BadRequest(msg) => {
                tracing::warn!(%msg, "SSH3 CONNECT rejected");
                response_with_status(StatusCode::BAD_REQUEST)
            }
            ConnectDecision::Unauthorized { www_authenticate } => unauthorized_response(&www_authenticate),
        }
    }

    async fn handle_accepted_connect<B>(
        &self,
        request: http::Request<B>,
        protocol: &Ssh3Protocol,
        stream_id: StreamId,
        version_header: HeaderValue,
        credential: Option<AuthCredential>,
    ) -> http::Response<Empty<bytes::Bytes>>
    where
        B: http_body::Body + Send + Unpin + 'static,
        B::Data: Send,
        B::Error: Send,
    {
        let (reserved, transport_server, transport_client) = match protocol.create_transport(stream_id, 16).await {
            Ok(bundle) => bundle,
            Err(e) => {
                tracing::error!(error = %Report::from_error(e), "failed to initialize SSH3 conversation");
                return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        let conversation_id = reserved.conversation_id();
        let readiness = Arc::new(AtomicBool::new(false));
        let global_requests = Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::default()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::default()),
            transport: transport_client.clone(),
            conversation_id,
        });
        tracing::info!(%conversation_id, "registered SSH3 conversation");

        let session_bin = match ssh3_session_binary() {
            Ok(path) if path.exists() => path,
            Ok(path) => {
                tracing::error!(error = %Report::from_error(ServerError::MissingSessionBinary { path: path.display().to_string() }), "ssh3-session binary not found");
                return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Err(e) => {
                tracing::error!(error = %Report::from_error(ServerError::ResolveSessionBinary { source: e }), "cannot determine executable path");
                return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let (child, mut child_bootstrap_tx, mut child_auth_rx) = match ChildProcess::spawn(&session_bin).await {
            Ok(tuple) => tuple,
            Err(e) => {
                tracing::error!(error = %Report::from_error(ServerError::SpawnChild { source: e }), "failed to spawn child process");
                return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

        let transport_server_handle = tokio::spawn(
            async move { let _ = transport_server.serve(true).await; }
                .instrument(tracing::info_span!("ssh3_transport_server", %conversation_id))
        );

        let bootstrap = ChildBootstrap {
            transport: transport_client,
            credential: credential.unwrap_or(AuthCredential::Basic {
                username: String::new(),
                password: String::new(),
            }),
            conversation_id,
        };
        if let Err(e) = reserved.transition_to_authenticating() {
            tracing::error!(error = %Report::from_error(e), %conversation_id, "failed to transition conversation to Authenticating");
            return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        }

        if let Err(e) = child_bootstrap_tx.send(bootstrap).await {
            tracing::error!(error = %Report::from_error(ServerError::SendBootstrap { message: e.to_string() }), %conversation_id, "failed to send ChildBootstrap to child");
            return response_with_status(StatusCode::INTERNAL_SERVER_ERROR);
        }

        match receive_auth_result(&mut child_auth_rx, conversation_id).await {
            AuthOutcome::Success => {
                let mut response = response_with_status(StatusCode::OK);
                response.headers_mut().insert("ssh-version", version_header);
                let readiness_for_supervisor = Arc::clone(&readiness);
                let global_requests_for_supervisor = Arc::clone(&global_requests);
                tokio::spawn(async move {
                    let lease = match reserved.consume_into_lease() {
                        Ok(lease) => lease,
                        Err(e) => {
                            tracing::warn!(error = %Report::from_error(e), %conversation_id, "failed to hand off reserved conversation to supervisor");
                            return;
                        }
                    };

                    let control_stream_start = tokio::sync::oneshot::channel::<io::Result<()>>();
                    let (control_stream_started_tx, control_stream_started_rx) = control_stream_start;
                    let mut control_stream_handle = tokio::spawn(
                        async move {
                            let (reader, writer) = upgrade::on(request)
                                .await
                                .map_err(|error| io::Error::other(format!("failed to take over SSH3 CONNECT stream: {error:?}")))?;
                            let _ = control_stream_started_tx.send(Ok(()));
                            serve_control_stream_global_requests(
                                reader,
                                writer,
                                readiness_for_supervisor,
                                Some(global_requests_for_supervisor),
                            )
                            .await
                        }
                        .instrument(tracing::info_span!("ssh3_control_stream", %conversation_id)),
                    );

                    if let Err(e) = lease.transition_to_active() {
                        tracing::warn!(error = %Report::from_error(e), %conversation_id, "failed to transition to Active");
                        control_stream_handle.abort();
                        return;
                    }

                    match control_stream_started_rx.await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(error = %Report::from_error(&error), %conversation_id, "control stream failed before readiness");
                            control_stream_handle.abort();
                            return;
                        }
                        Err(error) => {
                            tracing::warn!(error = %Report::from_error(error), %conversation_id, "control stream start signal dropped before readiness");
                            control_stream_handle.abort();
                            return;
                        }
                    }

                    readiness.store(true, Ordering::SeqCst);

                    let mut child = child;
                    let mut transport_server_handle = transport_server_handle;
                    tokio::select! {
                        status = child.wait() => {
                            match status {
                                Ok(status) => tracing::info!(?status, %conversation_id, "child process exited"),
                                Err(e) => tracing::warn!(error = %Report::from_error(e), %conversation_id, "error waiting for child"),
                            }
                        }
                        result = &mut transport_server_handle => {
                            match result {
                                Ok(_) => tracing::info!(%conversation_id, "transport server exited"),
                                Err(e) => tracing::warn!(error = %Report::from_error(e), %conversation_id, "transport server task panicked"),
                            }
                        }
                        result = &mut control_stream_handle => {
                            match result {
                                Ok(Ok(())) => tracing::info!(%conversation_id, "control stream handler exited"),
                                Ok(Err(e)) => tracing::warn!(error = %Report::from_error(e), %conversation_id, "control stream handler failed"),
                                Err(e) => tracing::warn!(error = %Report::from_error(e), %conversation_id, "control stream task panicked"),
                            }
                        }
                    }

                    readiness.store(false, Ordering::SeqCst);
                    if !transport_server_handle.is_finished() {
                        transport_server_handle.abort();
                    }
                    if !control_stream_handle.is_finished() {
                        control_stream_handle.abort();
                    }
                    if let Err(e) = child.kill() {
                        tracing::debug!(error = %Report::from_error(e), %conversation_id, "child already stopped during supervisor cleanup");
                    }
                    global_requests
                        .tcp_forwarder
                        .cleanup_for_owner(conversation_id)
                        .await;
                    global_requests
                        .streamlocal_forwarder
                        .cleanup_for_owner(conversation_id)
                        .await;

                    drop(lease);
                }
                .instrument(tracing::info_span!("ssh3_connection_supervisor", %conversation_id)));

                response
            }
            AuthOutcome::Unauthorized => unauthorized_response("Basic"),
        }
    }
}

impl Default for Ssh3ConnectHandler {
    fn default() -> Self {
        Self::new()
    }
}
impl<B> tower_service::Service<http::Request<B>> for Ssh3ConnectHandler
where
        B: http_body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Send,
{
    type Response = http::Response<Empty<bytes::Bytes>>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        request: http::Request<B>,
    ) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            Ok(handler.handle_request(request).await)
        })
    }
}

enum AuthOutcome {
    Success,
    Unauthorized,
}

async fn receive_auth_result(
    child_auth_rx: &mut remoc::rch::base::Receiver<AuthResult>,
    conversation_id: StreamId,
) -> AuthOutcome {
    match tokio::time::timeout(Duration::from_secs(30), child_auth_rx.recv()).await {
        Ok(Ok(Some(AuthResult::Success { .. }))) => {
            tracing::info!(%conversation_id, "PAM authentication succeeded via child");
            AuthOutcome::Success
        }
        Ok(Ok(Some(AuthResult::Failure { reason }))) => {
            tracing::warn!(%conversation_id, %reason, "PAM authentication failed via child");
            AuthOutcome::Unauthorized
        }
        Ok(Ok(None)) => {
            tracing::warn!(%conversation_id, "child closed channel without AuthResult");
            AuthOutcome::Unauthorized
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %Report::from_error(e), %conversation_id, "error receiving AuthResult from child");
            AuthOutcome::Unauthorized
        }
        Err(_) => {
            tracing::warn!(%conversation_id, "PAM authentication timed out (30s)");
            AuthOutcome::Unauthorized
        }
    }
}

fn response_with_status(status: StatusCode) -> http::Response<Empty<bytes::Bytes>> {
    let mut response = http::Response::new(Empty::new());
    *response.status_mut() = status;
    response
}

fn unauthorized_response(www_authenticate: &str) -> http::Response<Empty<bytes::Bytes>> {
    tracing::warn!("SSH3 CONNECT unauthorized");
    let mut response = response_with_status(StatusCode::UNAUTHORIZED);
    response.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        HeaderValue::from_str(www_authenticate)
            .unwrap_or_else(|_| HeaderValue::from_static("Basic")),
    );
    response
}

fn ssh3_session_binary() -> std::io::Result<std::path::PathBuf> {
    if let Ok(path) = std::env::var("SSH3_SESSION_BIN") {
        return Ok(std::path::PathBuf::from(path));
    }

    let exe = std::env::current_exe()?;
    let sibling = exe.parent().map(|p| p.join("ssh3-session")).unwrap_or_default();
    if sibling.exists() {
        return Ok(sibling);
    }

    Ok(exe.parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("ssh3-session"))
        .unwrap_or_default())
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
        let stream_id = StreamId::try_from(42u64).unwrap();
        let conversation_id = stream_id;
        assert_eq!(conversation_id, StreamId::try_from(42u64).unwrap());
    }
}
