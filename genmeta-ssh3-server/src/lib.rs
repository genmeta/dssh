//! SSH3 server implementation

use std::sync::Arc;

use gm_quic::{
    prelude::{
        BindUri,
        handy::{ToCertificate, ToPrivateKey},
    },
    qinterface::component::route::QuicRouter,
};
use genmeta_ssh::AuthCredential;
use genmeta_ssh::{AuthResult, ChildBootstrap};
use h3x::{
    connection::ConnectionBuilder,
    dhttp::settings::Settings,
    gm_quic::H3Servers,
    hyper::server::TowerService,
};
use tracing::Instrument;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub mod protocol;
pub mod auth;
pub mod error;
pub mod version;
pub mod handler;
pub mod session_driver;
pub mod child;
pub mod channel;
pub mod session;
pub mod forward;

pub fn init_server_tracing() -> tracing_appender::non_blocking::WorkerGuard {
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

pub fn init_session_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .try_init();
}

pub async fn run_server_from_env() -> Result<(), String> {
    let cert_path = std::env::var("SSH3_CERT_PATH")
        .map_err(|_| "error: SSH3_CERT_PATH environment variable is not set".to_string())?;
    let key_path = std::env::var("SSH3_KEY_PATH")
        .map_err(|_| "error: SSH3_KEY_PATH environment variable is not set".to_string())?;
    let bind_addr = std::env::var("SSH3_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:443".into());

    let cert_data = std::fs::read(&cert_path)
        .map_err(|e| format!("error: failed to read certificate from {cert_path}: {e}"))?;
    let key_data = std::fs::read(&key_path)
        .map_err(|e| format!("error: failed to read private key from {key_path}: {e}"))?;

    let handler = handler::Ssh3ConnectHandler::new();
    let service = TowerService(handler);

    let builder = ConnectionBuilder::new(Arc::new(Settings::default()))
        .protocol(protocol::Ssh3ProtocolFactory);

    let mut servers: H3Servers<_> = H3Servers::builder()
        .without_client_cert_verifier()
        .map_err(|e| format!("failed to initialize server TLS: {e}"))?
        .with_builder(Arc::new(builder))
        .with_router(Arc::new(QuicRouter::new()))
        .listen()
        .map_err(|e| format!("failed to listen: {e}"))?;

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
        .map_err(|e| format!("failed to add server: {e}"))?;

    tracing::info!("SSH3 server listening on {bind_addr}");

    let error = servers.run().await;
    Err(format!("server error: {error}"))
}

pub async fn run_session_from_stdio() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (conn, mut base_tx, mut base_rx): (
        _,
        remoc::rch::base::Sender<AuthResult>,
        remoc::rch::base::Receiver<ChildBootstrap>,
    ) = remoc::Connect::io(remoc::Cfg::default(), stdin, stdout).await?;
    tokio::spawn(conn.in_current_span());

    tracing::debug!("remoc connection established");

    let bootstrap = base_rx
        .recv()
        .await
        .map_err(std::io::Error::other)?
        .ok_or("parent closed base channel without sending ChildBootstrap")?;

    tracing::debug!("received ChildBootstrap from parent");

    let AuthCredential::Basic { username, password } = bootstrap.credential;
    let conversation_id = bootstrap.conversation_id;
    let auth_result = run_pam_auth(&username, &password).await;

    match &auth_result {
        AuthResult::Failure { reason } => {
            tracing::warn!(reason, "PAM authentication failed");
            let _ = base_tx.send(auth_result).await;
            return Ok(());
        }
        AuthResult::Success { .. } => {
            base_tx.send(auth_result.clone()).await?;
            tracing::debug!("sent AuthResult::Success to parent");
        }
    }

    if let AuthResult::Success {
        uid,
        gid,
        home,
        shell,
    } = auth_result
    {
        let init = genmeta_ssh::SessionInit {
            conversation_id,
            username,
            uid,
            gid,
            home,
            shell,
        };

        let session = session_driver::Ssh3Session::new(bootstrap.transport, init);
        session.run().await?;
    }

    Ok(())
}

#[cfg(feature = "pam")]
async fn run_pam_auth(username: &str, password: &str) -> AuthResult {
    let pam_backend = auth::pam::SystemPam;
    match auth::pam::pam_authenticate(&pam_backend, username, password).await {
        Ok(auth::pam::AuthResult::Success {
            uid,
            gid,
            home,
            shell,
        }) => AuthResult::Success {
            uid,
            gid,
            home,
            shell,
        },
        Ok(auth::pam::AuthResult::Failure { reason }) => AuthResult::Failure { reason },
        Err(pam_err) => AuthResult::Failure {
            reason: pam_err.to_string(),
        },
    }
}

#[cfg(not(feature = "pam"))]
async fn run_pam_auth(_username: &str, _password: &str) -> AuthResult {
    AuthResult::Failure {
        reason: "PAM support not compiled (missing `pam` feature)".into(),
    }
}
