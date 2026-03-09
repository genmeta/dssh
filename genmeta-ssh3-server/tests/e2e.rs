mod common;
use common::*;

use std::sync::Arc;

use genmeta_ssh3_server::handler::Ssh3ConnectHandler;
use genmeta_ssh3_server::protocol::Ssh3Protocol;
use h3x::qpack::field::Protocol;
use h3x::server::Router;
use http::{HeaderValue, Method};
use tokio_util::task::AbortOnDropHandle;

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
