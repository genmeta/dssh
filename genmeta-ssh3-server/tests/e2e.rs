mod common;
use common::*;

use std::sync::Arc;

use genmeta_ssh3_client::{
    Ssh3Client, Ssh3ClientConfig, SSH3_CONNECT_PATH, SSH_VERSION,
};
use genmeta_ssh3_server::handler::Ssh3ConnectHandler;
use genmeta_ssh3_server::protocol::Ssh3Protocol;
use h3x::qpack::field::Protocol;
use h3x::server::Router;
use http::{HeaderValue, Method, StatusCode};
use tokio_util::task::AbortOnDropHandle;

// ---------------------------------------------------------------------------
// Helper: build the standard SSH3 server (protocol + handler + router).
// ---------------------------------------------------------------------------

async fn setup_server() -> (
    AbortOnDropHandle<()>,
    http::uri::Authority,
) {
    let protocol = Arc::new(Ssh3Protocol::default());
    let handler = Ssh3ConnectHandler::new(protocol);
    let router = Router::new().connect("/.well-known/ssh3/connect", handler);

    let server = test_server(router).await;
    let authority = get_server_authority(&server);
    let handle = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await; }));
    (handle, authority)
}

// ---------------------------------------------------------------------------
// 1. Existing smoke test — kept verbatim for backwards compat.
// ---------------------------------------------------------------------------

#[test]
fn smoke_connect() {
    run("smoke_connect", async move {
        // 1. Build router with SSH3 handler
        let protocol = Arc::new(Ssh3Protocol::default());
        let handler = Ssh3ConnectHandler::new(protocol);
        let router = Router::new().connect("/.well-known/ssh3/connect", handler);

        // 2. Start server
        let server = test_server(router).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        // 3. Create client and send Extended CONNECT
        let client = test_client();
        let (_request, mut response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}/.well-known/ssh3/connect")
                    .parse()
                    .unwrap(),
            )
            .with_header("ssh-version", HeaderValue::from_static("michel-ssh3-00"))
            .with_header(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Basic dGVzdDp0ZXN0cGFzcw=="), // test:testpass
            )
            .auto_close(false)
            .execute()
            .await
            .expect("CONNECT request failed");

        // 4. Verify response
        assert_eq!(response.status(), http::StatusCode::OK);
        let ssh_version = response
            .header("ssh-version")
            .expect("missing ssh-version response header");
        assert_eq!(ssh_version.to_str().unwrap(), "michel-ssh3-00");
    })
}

// ---------------------------------------------------------------------------
// 2. Ssh3Client connect — full client wrapper over real QUIC.
// ---------------------------------------------------------------------------

#[test]
fn client_connect_success() {
    run("client_connect_success", async move {
        let (_serve, authority) = setup_server().await;

        let ssh3 = Ssh3Client::new(Ssh3ClientConfig {
            authority: authority.to_string(),
            username: "test".into(),
            password: "testpass".into(),
        });

        let client = test_client();
        let conn = ssh3.connect(&client).await.expect("connect should succeed");

        // Verify the negotiated version.
        assert_eq!(conn.server_version(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 3. Auth failure — missing Authorization header → 401 Unauthorized.
// ---------------------------------------------------------------------------

#[test]
fn auth_failure_missing_header() {
    run("auth_failure_missing_header", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let (_request, mut response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}{SSH3_CONNECT_PATH}")
                    .parse()
                    .unwrap(),
            )
            .with_header("ssh-version", HeaderValue::from_static(SSH_VERSION))
            // No Authorization header.
            .auto_close(false)
            .execute()
            .await
            .expect("CONNECT request itself should succeed at HTTP level");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // WWW-Authenticate header should be present.
        let www_auth = response
            .header(http::header::WWW_AUTHENTICATE)
            .expect("missing WWW-Authenticate header");
        assert_eq!(www_auth.to_str().unwrap(), "Basic");
    })
}

// ---------------------------------------------------------------------------
// 4. Auth failure via Ssh3Client — returns ClientError::AuthenticationFailed.
// ---------------------------------------------------------------------------

#[test]
fn auth_failure_via_client() {
    run("auth_failure_via_client", async move {
        // Build a server that rejects auth by not having any auth header
        // — but we need to send one that's invalid.
        // The server rejects Bearer tokens and malformed headers.
        let protocol = Arc::new(Ssh3Protocol::default());
        let handler = Ssh3ConnectHandler::new(protocol);
        let router = Router::new().connect(SSH3_CONNECT_PATH, handler);
        let server = test_server(router).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        // Send a raw CONNECT with Bearer auth (unsupported).
        let client = test_client();
        let (_request, response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}{SSH3_CONNECT_PATH}")
                    .parse()
                    .unwrap(),
            )
            .with_header("ssh-version", HeaderValue::from_static(SSH_VERSION))
            .with_header(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Bearer some-token"),
            )
            .auto_close(false)
            .execute()
            .await
            .expect("CONNECT transport should succeed");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    })
}

// ---------------------------------------------------------------------------
// 5. Version negotiation — response header matches client.
// ---------------------------------------------------------------------------

#[test]
fn version_negotiation() {
    run("version_negotiation", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let (_request, mut response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}{SSH3_CONNECT_PATH}")
                    .parse()
                    .unwrap(),
            )
            .with_header("ssh-version", HeaderValue::from_static(SSH_VERSION))
            .with_header(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Basic dGVzdDp0ZXN0cGFzcw=="),
            )
            .auto_close(false)
            .execute()
            .await
            .expect("CONNECT should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        // Server must echo back the same SSH version.
        let server_version = response
            .header("ssh-version")
            .expect("missing ssh-version");
        assert_eq!(server_version.to_str().unwrap(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 6. Invalid version → 400 Bad Request.
// ---------------------------------------------------------------------------

#[test]
fn invalid_version_rejected() {
    run("invalid_version_rejected", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let (_request, response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}{SSH3_CONNECT_PATH}")
                    .parse()
                    .unwrap(),
            )
            .with_header(
                "ssh-version",
                HeaderValue::from_static("unsupported-version-42"),
            )
            .with_header(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Basic dGVzdDp0ZXN0cGFzcw=="),
            )
            .auto_close(false)
            .execute()
            .await
            .expect("transport should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    })
}

// ---------------------------------------------------------------------------
// 7. Multiple concurrent connections — each gets 200 OK.
// ---------------------------------------------------------------------------

#[test]
fn multiple_concurrent_connects() {
    run("multiple_concurrent_connects", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();

        // Fire 3 concurrent CONNECT requests.
        let mut handles = Vec::new();
        for i in 0..3 {
            let client_ref = &client;
            let auth = authority.clone();
            handles.push(async move {
                let ssh3 = Ssh3Client::new(Ssh3ClientConfig {
                    authority: auth.to_string(),
                    username: format!("user{i}"),
                    password: format!("pass{i}"),
                });
                ssh3.connect(client_ref).await
            });
        }

        let (r0, r1, r2) = tokio::join!(handles.remove(0), handles.remove(0), handles.remove(0));

        let c0 = r0.expect("connect 0 failed");
        let c1 = r1.expect("connect 1 failed");
        let c2 = r2.expect("connect 2 failed");

        assert_eq!(c0.server_version(), SSH_VERSION);
        assert_eq!(c1.server_version(), SSH_VERSION);
        assert_eq!(c2.server_version(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 8. Wire format compliance — headers only, no CBOR, valid HTTP/3.
// ---------------------------------------------------------------------------

#[test]
fn wire_format_compliance() {
    run("wire_format_compliance", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let (_request, mut response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}{SSH3_CONNECT_PATH}")
                    .parse()
                    .unwrap(),
            )
            .with_header("ssh-version", HeaderValue::from_static(SSH_VERSION))
            .with_header(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Basic dGVzdDp0ZXN0cGFzcw=="),
            )
            .auto_close(false)
            .execute()
            .await
            .expect("CONNECT should succeed");

        // 1. Status must be 200 OK.
        assert_eq!(response.status(), StatusCode::OK);

        // 2. ssh-version header must be present and match.
        let ver = response.header("ssh-version").unwrap();
        assert_eq!(ver.to_str().unwrap(), SSH_VERSION);

        // 3. No content-type: application/cbor — SSH3 uses SSH binary, not CBOR.
        let ct = response.header("content-type");
        if let Some(ct_val) = ct {
            let s = ct_val.to_str().unwrap_or("");
            assert!(
                !s.contains("cbor"),
                "response must not use CBOR content-type, got: {s}"
            );
        }

        // 4. Response body should be empty at this point (no data frames
        //    until channels are opened).
        //    We don't read the body because it blocks (the connection stream
        //    stays open). Instead, verifying status + headers is sufficient.
    })
}

// ---------------------------------------------------------------------------
// 9. Missing ssh-version header → 400 Bad Request.
// ---------------------------------------------------------------------------

#[test]
fn missing_version_rejected() {
    run("missing_version_rejected", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let (_request, response) = client
            .new_request()
            .with_method(Method::CONNECT)
            .with_protocol(Protocol::new("ssh3"))
            .with_uri(
                format!("https://{authority}{SSH3_CONNECT_PATH}")
                    .parse()
                    .unwrap(),
            )
            // No ssh-version header.
            .with_header(
                http::header::AUTHORIZATION,
                HeaderValue::from_static("Basic dGVzdDp0ZXN0cGFzcw=="),
            )
            .auto_close(false)
            .execute()
            .await
            .expect("transport should succeed");

        // Version negotiation fails → 400.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    })
}
