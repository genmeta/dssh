#![allow(unused)]

use std::{
    error::Error,
    sync::{Arc, LazyLock},
    time::Duration,
};

use gm_quic::{
    prelude::{
        BindUri, BoundAddr, IO,
        handy::{ToCertificate, ToPrivateKey},
    },
    qinterface::component::route::QuicRouter,
};
use h3x::{
    connection::ConnectionBuilder,
    dhttp::settings::Settings,
    gm_quic::{H3Client, H3Servers},
    server::UnresolvedRequest,
};
use http::uri::Authority;
use tokio::time;
use tracing::{Instrument, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

pub const TEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn run<F: Future>(test_name: &'static str, future: F) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });

    static TRACING: LazyLock<WorkerGuard> = LazyLock::new(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(LevelFilter::DEBUG),
            )
            .with(tracing_subscriber::filter::filter_fn(|metadata| {
                !metadata.target().contains("netlink_packet_route")
            }))
            .init();
        guard
    });

    RT.block_on(async move {
        LazyLock::force(&TRACING);
        let test = future.instrument(tracing::info_span!("test", test_name));
        match time::timeout(TEST_TIMEOUT, test).await {
            Ok(output) => output,
            Err(_timedout) => panic!("test timed out"),
        }
    })
}

pub const CA_CERT: &[u8] = include_bytes!("../../../../h3x/tests/keychain/localhost/ca.cert");
pub const SERVER_CERT: &[u8] = include_bytes!("../../../../h3x/tests/keychain/localhost/server.cert");
pub const SERVER_KEY: &[u8] = include_bytes!("../../../../h3x/tests/keychain/localhost/server.key");

pub fn test_client() -> H3Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());
    H3Client::builder()
        .with_root_certificates(roots)
        .without_identity()
        .expect("failed to initialize client tls")
        .with_router(Arc::new(QuicRouter::new()))
        .build()
}

pub async fn test_server<S>(router: S) -> H3Servers<S>
where
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let builder = ConnectionBuilder::new(Arc::new(Settings::default()))
        .protocol(genmeta_ssh3_server::protocol::Ssh3ProtocolFactory);

    let mut servers = H3Servers::builder()
        .without_client_cert_verifier()
        .expect("failed to initialize server tls")
        .with_builder(Arc::new(builder))
        .with_router(Arc::new(QuicRouter::new()))
        .listen()
        .expect("failed to listen");
    servers
        .add_server(
            "localhost",
            SERVER_CERT.to_certificate(),
            SERVER_KEY.to_private_key(),
            None,
            [BindUri::from("inet://127.0.0.1:0").alloc_port()],
            router,
        )
        .await
        .expect("failed to add server");
    servers
}

pub fn get_server_addr<S>(servers: &H3Servers<S>) -> BoundAddr {
    let localhost = servers
        .quic_listener()
        .get_server("localhost")
        .expect("server localhost must be registered");
    let (_bind_uri, localhost_bind_interface) = localhost
        .bind_interfaces()
        .into_iter()
        .next()
        .expect("server localhost must have at least one bind interface");
    localhost_bind_interface
        .borrow()
        .bound_addr()
        .expect("bind interface must have local addr")
}

pub fn get_server_authority<S>(servers: &H3Servers<S>) -> Authority {
    match get_server_addr(servers) {
        BoundAddr::Internet(socket_addr) => {
            Authority::from_maybe_shared(Vec::from(format!("localhost:{}", socket_addr.port())))
                .expect("failed to parse authority")
        }
        _ => unimplemented!("Only Internet addresses are supported now"),
    }
}

// ---------------------------------------------------------------------------
// TestChannelService — a tower Service that handles SSH3 channels end-to-end.
//
// Unlike the production Ssh3ConnectHandler (which drops `_rx`), this service
// keeps the conversation receiver alive and spawns a task to dispatch incoming
// channel streams via `handle_channel`.
// ---------------------------------------------------------------------------

use std::{
    convert::Infallible,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::BoxFuture;
use genmeta_ssh3_server::{
    auth,
    channel,
    protocol::Ssh3Protocol,
    version,
};
use h3x::message::stream::MessageStreamError;
use h3x::protocol::Protocols;
use h3x::qpack::field::Protocol;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::{Empty, combinators::UnsyncBoxBody};
/// A test-only HTTP handler that fully processes SSH3 channels.
///
/// Validates the Extended CONNECT, registers a conversation, and spawns
/// a channel-dispatch loop that calls `handle_channel` for each stream.
#[derive(Clone)]
pub struct TestChannelService {
    next_conversation_id: Arc<AtomicU64>,
    #[allow(dead_code)]
    pam_backend: Option<Arc<dyn genmeta_ssh3_server::auth::pam::PamBackend>>,
}

impl TestChannelService {
    pub fn new(pam_backend: Option<Arc<dyn genmeta_ssh3_server::auth::pam::PamBackend>>) -> Self {
        Self {
            next_conversation_id: Arc::new(AtomicU64::new(0)),
            pam_backend,
        }
    }
}

impl tower_service::Service<http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>>
    for TestChannelService
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
        let next_id = self.next_conversation_id.clone();
        let pam_backend = self.pam_backend.clone();
        Box::pin(async move {
            // Look up the SSH3 protocol from request extensions.
            let protocols = request.extensions().get::<Arc<Protocols>>().cloned().unwrap();
            let protocol = protocols.get::<Ssh3Protocol>().expect("Ssh3Protocol not registered");

            let method = request.method().clone();
            let proto_str = request
                .extensions()
                .get::<Protocol>()
                .map(|p| p.as_str().to_owned());
            let headers = request.headers();

            let mut response = http::Response::new(Empty::new());

            // 1. Validate method is CONNECT.
            if method != Method::CONNECT {
                *response.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(response);
            }

            // 2. Validate :protocol is "ssh3".
            match proto_str.as_deref() {
                Some("ssh3") => {}
                _ => {
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            }

            // 3. Version negotiation.
            let version = match version::negotiate_version(headers) {
                Ok(v) => v,
                Err(_) => {
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }
            };

            // 4. Authentication.
            match auth::extract_auth_credential(headers) {
                Ok(credential) => {
                    // If a PAM backend is configured, verify credentials through it.
                    if let Some(ref pam) = pam_backend {
                        if let genmeta_ssh3_proto::auth::AuthCredential::Basic { ref username, ref password } = credential {
                            if let Err(_) = pam.authenticate("ssh3", username, password) {
                                *response.status_mut() = StatusCode::UNAUTHORIZED;
                                response.headers_mut().insert(
                                    http::header::WWW_AUTHENTICATE,
                                    HeaderValue::from_static("Basic"),
                                );
                                return Ok(response);
                            }
                        }
                    }
                }
                Err(challenge) => {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    response.headers_mut().insert(
                        http::header::WWW_AUTHENTICATE,
                        HeaderValue::from_str(&challenge.www_authenticate)
                            .unwrap_or_else(|_| HeaderValue::from_static("Basic")),
                    );
                    return Ok(response);
                }
            }

            // All checks passed — register conversation and KEEP rx alive.
            let conversation_id = next_id.fetch_add(1, Ordering::Relaxed);
            let mut rx = protocol.register_conversation(conversation_id).await;
            tracing::info!(conversation_id, "registered SSH3 conversation (test)");

            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .insert("ssh-version", version::version_response_header(&version));

            // Spawn a task that consumes dispatched channel streams.
            tokio::spawn(async move {
                while let Some((header, reader, writer)) = rx.recv().await {
                    // Spawn each channel handler independently.
                    tokio::spawn(async move {
                        if let Err(e) = channel::handle_channel(header, reader, writer).await {
                            tracing::warn!("channel handler error: {e}");
                        }
                    });
                }
            });

            Ok(response)
        })
    }
}
