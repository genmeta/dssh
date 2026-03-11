//! SSH3-over-QUIC production server binary.
//!
//! Reads TLS configuration from environment variables and starts an H3 server
//! with the SSH3 protocol handler.
//!
//! # Environment Variables
//!
//! - `SSH3_CERT_PATH` — path to the TLS certificate file (required)
//! - `SSH3_KEY_PATH` — path to the TLS private key file (required)
//! - `SSH3_BIND_ADDR` — bind address (default: `0.0.0.0:443`)

use std::sync::Arc;

use gm_quic::{
    prelude::{
        BindUri,
        handy::{ToCertificate, ToPrivateKey},
    },
    qinterface::component::route::QuicRouter,
};
use genmeta_ssh3_server::{handler::Ssh3ConnectHandler, protocol::Ssh3Protocol};
use h3x::{gm_quic::H3Servers, hyper::server::TowerService};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
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
}

#[tokio::main]
async fn main() {
    let _guard = init_tracing();

    let cert_path = match std::env::var("SSH3_CERT_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("error: SSH3_CERT_PATH environment variable is not set");
            std::process::exit(1);
        }
    };

    let key_path = match std::env::var("SSH3_KEY_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("error: SSH3_KEY_PATH environment variable is not set");
            std::process::exit(1);
        }
    };

    let bind_addr =
        std::env::var("SSH3_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:443".into());

    let cert_data = match std::fs::read(&cert_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: failed to read certificate from {cert_path}: {e}");
            std::process::exit(1);
        }
    };

    let key_data = match std::fs::read(&key_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: failed to read private key from {key_path}: {e}");
            std::process::exit(1);
        }
    };

    // Build the SSH3 handler chain.
    let protocol = Arc::new(Ssh3Protocol::default());
    let handler = Ssh3ConnectHandler::new(protocol);
    let service = TowerService(handler);

    // Build the H3/QUIC server using the same pattern as test infrastructure.
    let mut servers: H3Servers<_> = H3Servers::builder()
        .without_client_cert_verifier()
        .expect("failed to initialize server TLS")
        .with_router(Arc::new(QuicRouter::new()))
        .listen()
        .expect("failed to listen");

    let bind_uri = format!("inet://{bind_addr}");
    servers
        .add_server(
            "ssh3",
            cert_data.to_certificate(),
            key_data.to_private_key(),
            None,
            [BindUri::from(bind_uri.as_str())],
            service,
        )
        .await
        .expect("failed to add server");

    tracing::info!("SSH3 server listening on {bind_addr}");

    let error = servers.run().await;
    eprintln!("server error: {error}");
}
